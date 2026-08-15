// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Enterprise Notification Providers
 * ==================================================
 *
 * Full-featured, standalone enterprise provider management page.
 *
 *  Tab 1 · Providers
 *     • Channel overview dashboard (cards per channel with counts)
 *     • Full provider list with search, channel filter, status filter
 *     • Create / Edit provider with dynamic config schema forms
 *     • Toggle enable/disable inline
 *     • Verify connectivity in one click
 *     • Set / unset default per channel
 *     • Delete with confirmation
 *
 *  Tab 2 · Testing Console
 *     • Select a provider, enter a recipient, send test
 *     • Full debug output: request payload, response, timing
 *     • Test history log for the session
 *     • Bulk-test all providers for a channel
 *
 *  Tab 3 · Health & Diagnostics
 *     • Per-provider health card (verified status, last error, age, rate limits)
 *     • Channel readiness matrix
 *     • Config audit (masked) · click to reveal safe summary
 *     • Quick re-verify all button
 *
 *  Located at /notification-providers (/:tab)
 */

import { useState, useMemo, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useToast } from '@/hooks/use-toast';
import { motion, AnimatePresence } from 'framer-motion';
import { formatDistanceToNow, format, isValid } from 'date-fns';
import { z } from 'zod';
import {
  notificationApi,
  type NotificationProvider,
  type ProviderType,
  getApiErrorMessage,
} from '@/lib/api';
import { PageHeader, PageToolbar } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Badge } from '@/components/ui/badge';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { SearchBar } from '@/components/ui/search-bar';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';
import { Checkbox } from '@/components/ui/checkbox';
import { Separator } from '@/components/ui/separator';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
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
import { cn } from '@/lib/utils';
import { EmptyState } from '@/components/ui/empty-state';

import {
  Activity,
  AlertTriangle,
  ArrowUpDown,
  Bell,
  Bug,
  Check,
  CheckCircle,
  ChevronDown,
  Eye,
  EyeOff,
  Filter,
  Globe,
  Hash,
  Loader2,
  Mail,
  MessageCircle,
  MessageSquare,
  MoreHorizontal,
  Pencil,
  Play,
  Plus,
  Power,
  RefreshCw,
  Send,
  Settings2,
  ShieldCheck,
  Smartphone,
  Trash2,
  XCircle,
  Zap,
} from 'lucide-react';

// ═══════════════════════════════════════════════════════════════════
// Constants & Types
// ═══════════════════════════════════════════════════════════════════

const PAGE_TABS = ['providers', 'testing', 'health'] as const;
type PageTab = (typeof PAGE_TABS)[number];

// Tab labels/descriptions are translated at the use site via labelKey/descKey
// (module-level constants can't call the t() hook).
const TAB_META: Record<PageTab, { labelKey: string; icon: React.ElementType; descKey: string }> = {
  providers: { labelKey: 'tabs.providers.label', icon: Zap, descKey: 'tabs.providers.desc' },
  testing: { labelKey: 'tabs.testing.label', icon: Bug, descKey: 'tabs.testing.desc' },
  health: { labelKey: 'tabs.health.label', icon: Activity, descKey: 'tabs.health.desc' },
};

interface ConfigField {
  type: string;
  label: string;
  required?: boolean;
  placeholder?: string;
  default?: unknown;
  options?: string[];
}

interface TestLogEntry {
  id: string;
  providerId: string;
  providerName: string;
  channel: string;
  recipient: string;
  success: boolean;
  message: string;
  details?: Record<string, unknown>;
  durationMs: number;
  timestamp: Date;
}

// ── Channel icon / color maps ───────────────────────────────────────

const CHANNEL_ICONS: Record<string, React.ElementType> = {
  email: Mail,
  slack: Hash,
  teams: MessageSquare,
  webhook: Globe,
  sms: Smartphone,
  whatsapp: MessageCircle,
};

// Channel brand palette · uses opacity-based color (themes safely in dark mode).
// `badge` mirrors text+bg+border so the channel pill matches its icon tile.
const CHANNEL_COLORS: Record<string, { text: string; bg: string; border: string; badge: string }> = {
  email:    { text: 'text-blue-600 dark:text-blue-400',     bg: 'bg-blue-500/10',    border: 'border-blue-500/20',    badge: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20' },
  slack:    { text: 'text-purple-600 dark:text-purple-400', bg: 'bg-purple-500/10',  border: 'border-purple-500/20',  badge: 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/20' },
  teams:    { text: 'text-indigo-600 dark:text-indigo-400', bg: 'bg-indigo-500/10',  border: 'border-indigo-500/20',  badge: 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border-indigo-500/20' },
  webhook:  { text: 'text-emerald-600 dark:text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', badge: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20' },
  sms:      { text: 'text-amber-600 dark:text-amber-400',   bg: 'bg-amber-500/10',   border: 'border-amber-500/20',   badge: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20' },
  whatsapp: { text: 'text-green-600 dark:text-green-400',   bg: 'bg-green-500/10',   border: 'border-green-500/20',   badge: 'bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/20' },
};

function ChannelIcon({ channel, className }: { channel: string; className?: string }) {
  const Icon = CHANNEL_ICONS[channel] || Bell;
  return <Icon className={className} />;
}

function channelColor(channel: string) {
  return CHANNEL_COLORS[channel] || {
    text: 'text-muted-foreground', bg: 'bg-muted/50', border: 'border-muted', badge: 'bg-muted text-muted-foreground',
  };
}

// provider-type → human label for the type badge
function providerTypeLabel(type: string, types: ProviderType[]): string {
  return types.find((t) => t.type === type)?.name || type;
}

// ═══════════════════════════════════════════════════════════════════
// Shared Queries & Mutations
// ═══════════════════════════════════════════════════════════════════

function useProviders() {
  return useQuery({
    queryKey: ['notification-providers'],
    queryFn: () => notificationApi.getProviders().then((r) => r.data),
    staleTime: 30_000,
  });
}

function useProviderTypes() {
  return useQuery({
    queryKey: ['notification-provider-types'],
    queryFn: () => notificationApi.getProviderTypes().then((r) => r.data),
    staleTime: 300_000,
  });
}

// ═══════════════════════════════════════════════════════════════════
// Tab 1 · Providers
// ═══════════════════════════════════════════════════════════════════

// ── Channel Dashboard ────────────────────────────────────────────

function ChannelDashboard({ providers, types }: { providers: NotificationProvider[]; types: ProviderType[] }) {
  const { t } = useTranslation('enterprise');
  const channelStats = useMemo(() => {
    const allChannels = Array.from(new Set(types.map((t) => t.channel)));
    return allChannels.map((ch) => {
      const chProviders = providers.filter((p) => p.channel === ch);
      return {
        channel: ch,
        total: chProviders.length,
        enabled: chProviders.filter((p) => p.is_enabled).length,
        verified: chProviders.filter((p) => p.is_verified).length,
        hasDefault: chProviders.some((p) => p.is_default),
        errors: chProviders.filter((p) => p.last_error && p.is_enabled).length,
      };
    });
  }, [providers, types]);

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
      {channelStats.map(({ channel, total, enabled, verified, hasDefault, errors }) => {
        const c = channelColor(channel);
        return (
          <Card key={channel} className="overflow-hidden hover:shadow-md transition-shadow">
            <CardContent noOffset className="p-4 space-y-2">
              <div className="flex items-center justify-between">
                <div className={cn('flex h-9 w-9 items-center justify-center rounded-lg border', c.bg, c.border)}>
                  <ChannelIcon channel={channel} className={cn('h-4.5 w-4.5', c.text)} />
                </div>
                {errors > 0 && (
                  <Badge variant="destructive" className="text-[10px] px-1.5 py-0">
                    {t('NotificationProvidersPage.dashboard.errCount', { count: errors })}
                  </Badge>
                )}
              </div>
              <div>
                <p className="text-sm font-semibold capitalize">{channel}</p>
                <p className="text-xs text-muted-foreground">
                  {t('NotificationProvidersPage.dashboard.activeVerified', { enabled, total, verified })}
                </p>
              </div>
              <div className="flex items-center gap-1.5">
                {hasDefault ? (
                  <Badge variant="outline" className="text-[9px] px-1 py-0">{t('NotificationProvidersPage.dashboard.defaultSet')}</Badge>
                ) : total > 0 ? (
                  <Badge variant="outline" className="text-[9px] px-1 py-0 text-amber-600 border-amber-500/30">{t('NotificationProvidersPage.dashboard.noDefault')}</Badge>
                ) : null}
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

// ── Provider Row (Table Row) ─────────────────────────────────────

function ProviderRow({
  provider,
  types,
  selected,
  onSelectChange,
  onEdit,
  onDelete,
  onToggle,
  onVerify,
  onTest,
  onSetDefault,
  isVerifying,
}: {
  provider: NotificationProvider;
  types: ProviderType[];
  selected: boolean;
  onSelectChange: (checked: boolean) => void;
  onEdit: () => void;
  onDelete: () => void;
  onToggle: (enabled: boolean) => void;
  onVerify: () => void;
  onTest: () => void;
  onSetDefault: () => void;
  isVerifying: boolean;
}) {
  const { t } = useTranslation('enterprise');
  const c = channelColor(provider.channel);
  const age = provider.created_at && isValid(new Date(provider.created_at)) ? formatDistanceToNow(new Date(provider.created_at), { addSuffix: true }) : '-';
  const lastVerified = provider.last_verified_at && isValid(new Date(provider.last_verified_at))
    ? formatDistanceToNow(new Date(provider.last_verified_at), { addSuffix: true })
    : t('NotificationProvidersPage.common.never');

  return (
    <motion.tr
      layout
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className={cn(
        'group border-b last:border-0 hover:bg-muted/30 transition-colors',
        !provider.is_enabled && 'opacity-50',
      )}
    >
      {/* Selection */}
      <td className="px-4 py-3 w-10">
        <Checkbox
          checked={selected}
          onCheckedChange={(v) => onSelectChange(!!v)}
          aria-label={t('common:DataTable.selectRow')}
        />
      </td>

      {/* Name + Type */}
      <td className="px-4 py-3">
        <div className="flex items-center gap-3">
          <div className={cn('flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border', c.bg, c.border)}>
            <ChannelIcon channel={provider.channel} className={cn('h-4 w-4', c.text)} />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-medium text-sm truncate">{provider.name}</span>
              {provider.is_default && (
                <Badge variant="secondary" className="text-[9px] px-1.5 py-0 shrink-0">{t('NotificationProvidersPage.common.default')}</Badge>
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              {providerTypeLabel(provider.provider_type, types)}
            </p>
          </div>
        </div>
      </td>

      {/* Channel */}
      <td className="px-4 py-3">
        <Badge className={cn('text-[10px]', c.badge)} variant="outline">
          {provider.channel}
        </Badge>
      </td>

      {/* Status */}
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          {provider.is_verified ? (
            <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-emerald-600 dark:text-emerald-400 border-emerald-500/30">
              <CheckCircle className="h-3 w-3 mr-1" /> {t('NotificationProvidersPage.status.verified')}
            </Badge>
          ) : (
            <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-amber-600 dark:text-amber-400 border-amber-500/30">
              <AlertTriangle className="h-3 w-3 mr-1" /> {t('NotificationProvidersPage.status.unverified')}
            </Badge>
          )}
          {provider.last_error && provider.is_enabled && (
            <Badge variant="destructive" className="text-[10px] px-1.5 py-0 max-w-[160px] truncate">
              {provider.last_error}
            </Badge>
          )}
        </div>
      </td>

      {/* Last Verified */}
      <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
        {lastVerified}
      </td>

      {/* Rate Limits */}
      <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
        {(provider.rate_limit_per_hour ?? 0).toLocaleString()}/h · {(provider.rate_limit_per_day ?? 0).toLocaleString()}/d
      </td>

      {/* Created */}
      <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">{age}</td>

      {/* Enabled */}
      <td className="px-4 py-3">
        <Switch checked={provider.is_enabled} onCheckedChange={(v) => onToggle(v)} />
      </td>

      {/* Actions */}
      <td className="px-4 py-3">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8 opacity-0 group-hover:opacity-100 transition-opacity">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-52">
            <DropdownMenuItem onClick={onEdit}>
              <Pencil className="mr-2 h-4 w-4" /> {t('NotificationProvidersPage.row.editConfig')}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={onVerify} disabled={isVerifying}>
              {isVerifying ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
              {t('NotificationProvidersPage.row.verifyConnection')}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={onTest}>
              <Send className="mr-2 h-4 w-4" /> {t('NotificationProvidersPage.row.sendTest')}
            </DropdownMenuItem>
            {!provider.is_default && (
              <DropdownMenuItem onClick={onSetDefault}>
                <Check className="mr-2 h-4 w-4" /> {t('NotificationProvidersPage.row.setDefault')}
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={onDelete} className="text-destructive focus:text-destructive">
              <Trash2 className="mr-2 h-4 w-4" /> {t('NotificationProvidersPage.row.deleteProvider')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </td>
    </motion.tr>
  );
}

// ── Provider Form Dialog ─────────────────────────────────────────

// FormDialog values: dialog-level fields plus a free-form `config` blob.
// Per-provider field schemas are dynamic (delivered by the backend in
// `ProviderType.config_schema`), so a static `z.discriminatedUnion` over a
// hardcoded list of providers would be both impossible (no compile-time
// list) and brittle (would silently break when the backend adds a new
// provider). Instead we use a single object schema + a `superRefine` that
// walks the selected provider type's config_schema at validation time.
// Validation messages are translated via the `t` passed from the component
// (module-level schema can't call the t() hook directly).
const buildProviderFormSchema = (t: (key: string) => string) =>
  z.object({
    name: z.string().min(1, t('NotificationProvidersPage.form.validation.nameRequired')),
    provider_type: z.string().min(1, t('NotificationProvidersPage.form.validation.typeRequired')),
    config: z.record(z.string(), z.unknown()),
    is_enabled: z.boolean(),
    is_default: z.boolean(),
    rate_limit_per_hour: z.coerce.number().int().min(0, t('NotificationProvidersPage.form.validation.zeroOrGreater')),
    rate_limit_per_day: z.coerce.number().int().min(0, t('NotificationProvidersPage.form.validation.zeroOrGreater')),
  });
type ProviderFormValues = z.infer<ReturnType<typeof buildProviderFormSchema>>;

// Build a refined schema closed over the live providerTypes list so
// per-provider required fields surface as proper FormMessage errors.
function buildProviderSchema(
  providerTypes: ProviderType[],
  t: (key: string, opts?: Record<string, unknown>) => string,
) {
  return buildProviderFormSchema(t).superRefine((data, ctx) => {
    const pt = providerTypes.find((t2) => t2.type === data.provider_type);
    if (!pt) return;
    const cs = (pt.config_schema || {}) as Record<string, ConfigField>;
    for (const [key, field] of Object.entries(cs)) {
      if (!field.required) continue;
      const v = data.config?.[key];
      const empty =
        v === undefined ||
        v === null ||
        (typeof v === 'string' && v.trim() === '');
      if (empty) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['config', key],
          message: t('NotificationProvidersPage.form.validation.fieldRequired', { field: field.label }),
        });
      }
    }
  });
}

// ── JSON config field ────────────────────────────────────────────
//
// Some provider config fields are typed ``json`` (e.g. the Generic Webhook's
// custom headers map). The backend expects an object/dict for these, so a
// plain text Input, which submits a *string*, makes the WebhookProvider
// crash. This editor keeps a local raw-text buffer so the user can type
// freely (including transiently-invalid JSON) without React Hook Form ever
// receiving a malformed value: the parsed object is only committed to the
// form when the text parses cleanly. While the text is invalid we surface an
// inline hint and leave the last valid object in the form state.
function JsonConfigField({
  value,
  onChange,
  onBlur,
  name,
  placeholder,
  fallback,
}: {
  value: unknown;
  onChange: (next: unknown) => void;
  onBlur: () => void;
  name: string;
  placeholder?: string;
  fallback: unknown;
}) {
  const { t } = useTranslation('enterprise');
  const [raw, setRaw] = useState(() => {
    try {
      return JSON.stringify(value ?? fallback ?? {}, null, 2);
    } catch {
      return '{}';
    }
  });
  const [invalid, setInvalid] = useState(false);

  const handleChange = (text: string) => {
    setRaw(text);
    // An empty buffer is treated as "no value" (empty object) rather than a
    // parse error, so clearing the field doesn't show a spurious warning.
    if (text.trim() === '') {
      setInvalid(false);
      onChange({});
      return;
    }
    try {
      const parsed = JSON.parse(text);
      setInvalid(false);
      onChange(parsed);
    } catch {
      // Keep the raw text on screen; do not commit a malformed value.
      setInvalid(true);
    }
  };

  return (
    <>
      <Textarea
        className={cn('font-mono text-xs min-h-[96px]', invalid && 'border-destructive')}
        placeholder={placeholder || '{\n  "X-Custom-Header": "value"\n}'}
        value={raw}
        onChange={(e) => handleChange(e.target.value)}
        onBlur={onBlur}
        name={name}
        spellCheck={false}
      />
      {invalid && (
        <p className="text-xs text-destructive">
          {t('NotificationProvidersPage.form.invalidJson')}
        </p>
      )}
    </>
  );
}

function ProviderFormDialog({
  open,
  onOpenChange,
  providerTypes,
  existingProvider,
  onSubmit,
  isSubmitting,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  providerTypes: ProviderType[];
  existingProvider?: NotificationProvider | null;
  onSubmit: (data: {
    name: string;
    provider_type: string;
    config: Record<string, unknown>;
    is_enabled: boolean;
    is_default: boolean;
    rate_limit_per_hour: number;
    rate_limit_per_day: number;
  }) => void;
  isSubmitting: boolean;
}) {
  const { t } = useTranslation('enterprise');
  // Wizard step is local UI state · not part of the form values.
  const [step, setStep] = useState<'type' | 'config'>(existingProvider ? 'config' : 'type');

  // Keep step in sync with open / mode transitions.
  useEffect(() => {
    if (open) setStep(existingProvider ? 'config' : 'type');
  }, [open, existingProvider]);

  const schema = useMemo(() => buildProviderSchema(providerTypes, t), [providerTypes, t]);

  // defaultValues are recomputed when switching create/edit; FormDialog
  // resets the form when `open` flips to true.
  const defaultValues = useMemo<ProviderFormValues>(() => {
    if (existingProvider) {
      return {
        name: existingProvider.name,
        provider_type: existingProvider.provider_type,
        config: existingProvider.config_summary ? { ...existingProvider.config_summary } : {},
        is_enabled: existingProvider.is_enabled,
        is_default: existingProvider.is_default,
        rate_limit_per_hour: existingProvider.rate_limit_per_hour,
        rate_limit_per_day: existingProvider.rate_limit_per_day,
      };
    }
    return {
      name: '',
      provider_type: '',
      config: {},
      is_enabled: true,
      is_default: false,
      rate_limit_per_hour: 500,
      rate_limit_per_day: 10000,
    };
  }, [existingProvider]);

  const groupedTypes = useMemo(() => {
    const map = new Map<string, ProviderType[]>();
    for (const t of providerTypes) {
      const list = map.get(t.channel) || [];
      list.push(t);
      map.set(t.channel, list);
    }
    return map;
  }, [providerTypes]);

  const title = existingProvider
    ? t('NotificationProvidersPage.form.title.edit')
    : step === 'type'
    ? t('NotificationProvidersPage.form.title.selectType')
    : t('NotificationProvidersPage.form.title.configure');

  return (
    <FormDialog<ProviderFormValues>
      open={open}
      onOpenChange={onOpenChange}
      title={title}
      schema={schema}
      defaultValues={defaultValues}
      submitLabel={existingProvider ? t('NotificationProvidersPage.form.submit.save') : t('NotificationProvidersPage.form.submit.create')}
      // Disable submit on the type-picker step (create only) · the form is
      // not yet meaningful until a provider type has been chosen.
      submitDisabled={!existingProvider && step === 'type'}
      contentClassName="max-w-2xl max-h-[90vh] overflow-y-auto"
      onSubmit={(values) => {
        onSubmit({
          name: values.name,
          provider_type: values.provider_type,
          config: values.config,
          is_enabled: values.is_enabled,
          is_default: values.is_default,
          rate_limit_per_hour: values.rate_limit_per_hour,
          rate_limit_per_day: values.rate_limit_per_day,
        });
      }}
    >
      {(form) => {
        const selectedType = form.watch('provider_type');
        const pt = providerTypes.find((t) => t.type === selectedType);
        const cs = (pt?.config_schema || {}) as Record<string, ConfigField>;

        const selectType = (t: ProviderType) => {
          form.setValue('provider_type', t.type, { shouldValidate: false });
          // Seed display name from the type name if user hasn't entered one yet.
          if (!form.getValues('name')) {
            form.setValue('name', t.name, { shouldValidate: false });
          }
          // Apply field defaults from the new type's config_schema.
          const next = (t.config_schema || {}) as Record<string, ConfigField>;
          const defaults: Record<string, unknown> = {};
          for (const [k, v] of Object.entries(next)) {
            if (v.default !== undefined) defaults[k] = v.default;
          }
          form.setValue('config', defaults, { shouldValidate: false });
          setStep('config');
        };

        return (
          <>
            {/* Description (mirrors the original DialogDescription) */}
            <p className="text-sm text-muted-foreground -mt-2">
              {existingProvider
                ? t('NotificationProvidersPage.form.description.edit', { name: existingProvider.name })
                : step === 'type'
                ? t('NotificationProvidersPage.form.description.selectType')
                : t('NotificationProvidersPage.form.description.configure', { type: pt?.name || selectedType })}
            </p>

            {/* Step 1: Type selection (create only) */}
            {step === 'type' && !existingProvider && (
              <div className="space-y-4 py-2">
                {[...groupedTypes.entries()].map(([channel, types]) => {
                  const c = channelColor(channel);
                  return (
                    <div key={channel}>
                      <div className="flex items-center gap-2 mb-2">
                        <ChannelIcon channel={channel} className={cn('h-4 w-4', c.text)} />
                        <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground capitalize">
                          {channel}
                        </p>
                      </div>
                      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                        {types.map((t) => (
                          <button
                            key={t.type}
                            type="button"
                            onClick={() => selectType(t)}
                            className={cn(
                              'flex items-center gap-3 rounded-lg border p-3 text-left text-sm transition-all hover:shadow-sm',
                              selectedType === t.type
                                ? 'border-primary bg-primary/5 ring-1 ring-primary/30'
                                : 'border-muted hover:border-muted-foreground/30',
                            )}
                          >
                            <div
                              className={cn(
                                'flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border',
                                c.bg,
                                c.border,
                              )}
                            >
                              <ChannelIcon channel={channel} className={cn('h-4 w-4', c.text)} />
                            </div>
                            <div className="min-w-0">
                              <div className="font-medium truncate">{t.name}</div>
                              <div className="text-[11px] text-muted-foreground">{t.type}</div>
                            </div>
                          </button>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Step 2: Configuration */}
            {step === 'config' && (
              <div className="space-y-5 py-2">
                {/* Back to type selection (create only) */}
                {!existingProvider && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => setStep('type')}
                    className="text-xs -ml-2"
                  >
                    <ChevronDown className="mr-1 h-3 w-3 rotate-90" /> {t('NotificationProvidersPage.form.changeType')}
                  </Button>
                )}

                {/* Provider identity */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="name"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>
                          {t('NotificationProvidersPage.form.displayName')} <span className="text-destructive">*</span>
                        </FormLabel>
                        <FormControl>
                          <Input placeholder={t('NotificationProvidersPage.form.displayNamePlaceholder')} {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <div className="space-y-2">
                    <Label className="text-sm text-muted-foreground">{t('NotificationProvidersPage.form.providerType')}</Label>
                    <div className="flex items-center gap-2 h-9 px-3 rounded-md border bg-muted/30">
                      <ChannelIcon
                        channel={pt?.channel || ''}
                        className="h-4 w-4 text-muted-foreground"
                      />
                      <span className="text-sm">{pt?.name || selectedType}</span>
                      <Badge variant="secondary" className="ml-auto text-[10px]">
                        {pt?.channel}
                      </Badge>
                    </div>
                  </div>
                </div>

                {/* Dynamic config fields · driven by the selected provider type's
                    config_schema. Required-field validation is enforced via the
                    schema's superRefine and surfaces in <FormMessage>. */}
                {Object.keys(cs).length > 0 && (
                  <div className="space-y-4 rounded-lg border p-4 bg-muted/20">
                    <div className="flex items-center gap-2">
                      <Settings2 className="h-4 w-4 text-muted-foreground" />
                      <p className="text-sm font-medium">{t('NotificationProvidersPage.form.configuration')}</p>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      {Object.entries(cs).map(([key, fieldDef]) => (
                        <FormField
                          key={key}
                          control={form.control}
                          name={`config.${key}` as const}
                          render={({ field }) => (
                            <FormItem
                              className={cn((fieldDef.type === 'password' || fieldDef.type === 'json') && 'sm:col-span-2')}
                            >
                              <FormLabel className="text-xs">
                                {fieldDef.label}
                                {fieldDef.required && (
                                  <span className="text-destructive ml-0.5">*</span>
                                )}
                              </FormLabel>
                              <FormControl>
                                {fieldDef.type === 'json' ? (
                                  <JsonConfigField
                                    value={field.value}
                                    onChange={field.onChange}
                                    onBlur={field.onBlur}
                                    name={field.name}
                                    placeholder={fieldDef.placeholder}
                                    fallback={fieldDef.default}
                                  />
                                ) : fieldDef.type === 'boolean' ? (
                                  <div className="flex items-center gap-2 h-9">
                                    <Switch
                                      checked={!!field.value}
                                      onCheckedChange={(v) => field.onChange(v)}
                                    />
                                    <span className="text-xs text-muted-foreground">
                                      {field.value ? t('NotificationProvidersPage.form.enabled') : t('NotificationProvidersPage.form.disabled')}
                                    </span>
                                  </div>
                                ) : fieldDef.type === 'select' ? (
                                  <Select
                                    value={String(field.value ?? fieldDef.default ?? '')}
                                    onValueChange={(v) => field.onChange(v)}
                                  >
                                    <SelectTrigger>
                                      <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                      {(fieldDef.options || []).map((opt) => (
                                        <SelectItem key={opt} value={opt}>
                                          {opt}
                                        </SelectItem>
                                      ))}
                                    </SelectContent>
                                  </Select>
                                ) : (
                                  <Input
                                    type={
                                      fieldDef.type === 'password'
                                        ? 'password'
                                        : fieldDef.type === 'number'
                                        ? 'number'
                                        : 'text'
                                    }
                                    // Without ``new-password`` Chrome
                                    // offers the admin's *own* login
                                    // password as autofill for the
                                    // SMTP/webhook secret fields and
                                    // may save admin-entered secrets
                                    // into the browser's password
                                    // manager.
                                    autoComplete={fieldDef.type === 'password' ? 'new-password' : 'off'}
                                    placeholder={fieldDef.placeholder || ''}
                                    value={String(field.value ?? '')}
                                    onChange={(e) =>
                                      field.onChange(
                                        fieldDef.type === 'number'
                                          ? e.target.value === ''
                                            ? ''
                                            : Number(e.target.value)
                                          : e.target.value,
                                      )
                                    }
                                    onBlur={field.onBlur}
                                    name={field.name}
                                    ref={field.ref}
                                  />
                                )}
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      ))}
                    </div>
                  </div>
                )}

                <Separator />

                {/* Behavior */}
                <div className="space-y-4">
                  <p className="text-sm font-medium">{t('NotificationProvidersPage.form.behavior')}</p>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                    <FormField
                      control={form.control}
                      name="is_enabled"
                      render={({ field }) => (
                        <FormItem className="flex items-center gap-2 space-y-0">
                          <FormControl>
                            <Switch
                              checked={field.value}
                              onCheckedChange={field.onChange}
                            />
                          </FormControl>
                          <FormLabel className="text-sm !mt-0">{t('NotificationProvidersPage.form.enabled')}</FormLabel>
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={form.control}
                      name="is_default"
                      render={({ field }) => (
                        <FormItem className="flex items-center gap-2 space-y-0">
                          <FormControl>
                            <Switch
                              checked={field.value}
                              onCheckedChange={field.onChange}
                            />
                          </FormControl>
                          <FormLabel className="text-sm !mt-0">{t('NotificationProvidersPage.form.default')}</FormLabel>
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={form.control}
                      name="rate_limit_per_hour"
                      render={({ field }) => (
                        <FormItem className="space-y-1">
                          <FormLabel className="text-xs text-muted-foreground">
                            {t('NotificationProvidersPage.form.ratePerHour')}
                          </FormLabel>
                          <FormControl>
                            <Input
                              type="number"
                              min={0}
                              className="h-8"
                              value={field.value ?? ''}
                              onChange={(e) =>
                                field.onChange(
                                  e.target.value === '' ? 0 : Number(e.target.value),
                                )
                              }
                              onBlur={field.onBlur}
                              name={field.name}
                              ref={field.ref}
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={form.control}
                      name="rate_limit_per_day"
                      render={({ field }) => (
                        <FormItem className="space-y-1">
                          <FormLabel className="text-xs text-muted-foreground">
                            {t('NotificationProvidersPage.form.ratePerDay')}
                          </FormLabel>
                          <FormControl>
                            <Input
                              type="number"
                              min={0}
                              className="h-8"
                              value={field.value ?? ''}
                              onChange={(e) =>
                                field.onChange(
                                  e.target.value === '' ? 0 : Number(e.target.value),
                                )
                              }
                              onBlur={field.onBlur}
                              name={field.name}
                              ref={field.ref}
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>
                </div>

                {/* Surface a non-blocking spinner when parent mutation is in
                    flight. FormDialog manages its own submit-button spinner
                    via form.formState.isSubmitting, but the parent's
                    mutate-and-forget pattern means we hint at activity here. */}
                {isSubmitting && (
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Loader2 className="h-3 w-3 animate-spin" />
                    {t('NotificationProvidersPage.form.saving')}
                  </div>
                )}
              </div>
            )}
          </>
        );
      }}
    </FormDialog>
  );
}

// ── Providers Tab ────────────────────────────────────────────────

function ProvidersTab() {
  const { t } = useTranslation('enterprise');
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // Centralized error helper, the 6 mutations below previously had no
  // ``onError`` at all, so 403/404/422 from the backend hit a closed
  // dialog and silent failure. This surfaces a destructive toast with
  // the server detail when available.
  const errToast = (title: string) => (err: unknown) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const detail = (err as any)?.response?.data?.detail
      || (err instanceof Error ? err.message : t('NotificationProvidersPage.toast.unknownError'));
    toast({ variant: 'destructive', title, description: String(detail) });
  };
  const { data: providers = [], isLoading } = useProviders();
  const { data: providerTypes = [] } = useProviderTypes();

  // UI state
  const [search, setSearch] = useState('');
  const [channelFilter, setChannelFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'enabled' | 'disabled' | 'error'>('all');
  const [sortField, setSortField] = useState<'name' | 'channel' | 'created_at'>('name');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [formOpen, setFormOpen] = useState(false);
  const [editingProvider, setEditingProvider] = useState<NotificationProvider | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<NotificationProvider | null>(null);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [selectedProviders, setSelectedProviders] = useState<NotificationProvider[]>([]);

  // Mutations
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['notification-providers'] });

  const createMut = useMutation({
    mutationFn: (data: Parameters<typeof notificationApi.createProvider>[0]) =>
      notificationApi.createProvider(data),
    onSuccess: () => { invalidate(); setFormOpen(false); },
    onError: errToast(t('NotificationProvidersPage.toast.createFailed')),
  });

  const updateMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof notificationApi.updateProvider>[1] }) =>
      notificationApi.updateProvider(id, data),
    onSuccess: () => { invalidate(); setFormOpen(false); setEditingProvider(null); },
    onError: errToast(t('NotificationProvidersPage.toast.updateFailed')),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => notificationApi.deleteProvider(id),
    onSuccess: () => { invalidate(); setDeleteTarget(null); },
    onError: errToast(t('NotificationProvidersPage.toast.deleteFailed')),
  });

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      notificationApi.updateProvider(id, { is_enabled: enabled }),
    onSuccess: invalidate,
    onError: errToast(t('NotificationProvidersPage.toast.toggleFailed')),
  });

  const verifyMut = useMutation({
    mutationFn: (id: string) => notificationApi.verifyProvider(id),
    onSuccess: () => { invalidate(); setVerifyingId(null); },
    onError: (err) => {
      invalidate();
      setVerifyingId(null);
      errToast(t('NotificationProvidersPage.toast.verifyFailed'))(err);
    },
  });

  const setDefaultMut = useMutation({
    mutationFn: (id: string) => notificationApi.updateProvider(id, { is_default: true }),
    onSuccess: invalidate,
    onError: errToast(t('NotificationProvidersPage.toast.setDefaultFailed')),
  });

  // Filtering + sorting
  const filteredProviders = useMemo(() => {
    let list = [...providers];

    if (search) {
      const q = search.toLowerCase();
      list = list.filter((p) =>
        p.name.toLowerCase().includes(q) || p.provider_type.toLowerCase().includes(q) || p.channel.includes(q),
      );
    }
    if (channelFilter !== 'all') list = list.filter((p) => p.channel === channelFilter);
    if (statusFilter === 'enabled') list = list.filter((p) => p.is_enabled);
    if (statusFilter === 'disabled') list = list.filter((p) => !p.is_enabled);
    if (statusFilter === 'error') list = list.filter((p) => p.last_error && p.is_enabled);

    list.sort((a, b) => {
      const fieldA = a[sortField] || '';
      const fieldB = b[sortField] || '';
      const cmp = String(fieldA).localeCompare(String(fieldB));
      return sortDir === 'asc' ? cmp : -cmp;
    });

    return list;
  }, [providers, search, channelFilter, statusFilter, sortField, sortDir]);

  const allChannels = useMemo(() => Array.from(new Set(providerTypes.map((t) => t.channel))), [providerTypes]);

  // Fast membership lookup for the row + header checkboxes.
  const selectedIds = useMemo(() => new Set(selectedProviders.map((p) => p.id)), [selectedProviders]);
  const toggleRowSelection = (provider: NotificationProvider, checked: boolean) => {
    setSelectedProviders((prev) =>
      checked ? [...prev.filter((p) => p.id !== provider.id), provider] : prev.filter((p) => p.id !== provider.id),
    );
  };

  const handleFormSubmit = (data: {
    name: string;
    provider_type: string;
    config: Record<string, unknown>;
    is_enabled: boolean;
    is_default: boolean;
    rate_limit_per_hour: number;
    rate_limit_per_day: number;
  }) => {
    if (editingProvider) {
      updateMut.mutate({
        id: editingProvider.id,
        data: {
          name: data.name,
          config: data.config,
          is_enabled: data.is_enabled,
          is_default: data.is_default,
          rate_limit_per_hour: data.rate_limit_per_hour,
          rate_limit_per_day: data.rate_limit_per_day,
        },
      });
    } else {
      createMut.mutate(data);
    }
  };

  const handleSort = (field: typeof sortField) => {
    if (sortField === field) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortField(field); setSortDir('asc'); }
  };

  const openEdit = (p: NotificationProvider) => { setEditingProvider(p); setFormOpen(true); };
  const openCreate = () => { setEditingProvider(null); setFormOpen(true); };

  // Quick verify for a single provider
  const handleVerify = (id: string) => { setVerifyingId(id); verifyMut.mutate(id); };

  // Navigate to test tab with provider pre-selected
  const navigate = useNavigate();
  const handleTest = (p: NotificationProvider) => {
    navigate(`/notification-providers/testing?provider=${p.id}`);
  };

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Channel Dashboard */}
      <ChannelDashboard providers={providers} types={providerTypes} />

      {/* Toolbar */}
      <PageToolbar>
        <SearchBar
          value={search}
          onChange={setSearch}
          placeholder={t('NotificationProvidersPage.toolbar.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        <Select value={channelFilter} onValueChange={setChannelFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <Filter className="mr-2 h-3.5 w-3.5 text-muted-foreground" />
            <SelectValue placeholder={t('NotificationProvidersPage.toolbar.channel')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('NotificationProvidersPage.toolbar.allChannels')}</SelectItem>
            {allChannels.map((ch) => (
              <SelectItem key={ch} value={ch} className="capitalize">{ch}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={(v: typeof statusFilter) => setStatusFilter(v)}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={t('NotificationProvidersPage.toolbar.status')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('NotificationProvidersPage.toolbar.allStatus')}</SelectItem>
            <SelectItem value="enabled">{t('NotificationProvidersPage.toolbar.statusEnabled')}</SelectItem>
            <SelectItem value="disabled">{t('NotificationProvidersPage.toolbar.statusDisabled')}</SelectItem>
            <SelectItem value="error">{t('NotificationProvidersPage.toolbar.statusError')}</SelectItem>
          </SelectContent>
        </Select>
        {(search !== '' || channelFilter !== 'all' || statusFilter !== 'all') && (
          <Button variant="ghost" size="sm" onClick={() => { setSearch(''); setChannelFilter('all'); setStatusFilter('all'); }}>
            {t('NotificationProvidersPage.toolbar.clearFilters')}
          </Button>
        )}
        <Badge variant="secondary" className="text-xs tabular-nums h-6">
          {t('NotificationProvidersPage.toolbar.countOf', { shown: filteredProviders.length, total: providers.length })}
        </Badge>
        <Button variant="outline" size="sm" onClick={() => queryClient.invalidateQueries({ queryKey: ['notification-providers'] })}>
          <RefreshCw className="mr-2 h-3.5 w-3.5" /> {t('NotificationProvidersPage.toolbar.refresh')}
        </Button>
        <Button size="sm" onClick={openCreate}>
          <Plus className="mr-2 h-4 w-4" /> {t('NotificationProvidersPage.toolbar.addProvider')}
        </Button>
      </PageToolbar>

      {/* Provider table */}
      {filteredProviders.length === 0 ? (
        <Card>
          <CardContent noOffset className="py-4">
            <EmptyState
              icon={Bell}
              title={t('NotificationProvidersPage.empty.title')}
              description={
                providers.length > 0
                  ? t('NotificationProvidersPage.empty.filtered')
                  : t('NotificationProvidersPage.empty.none')
              }
              action={providers.length === 0 ? { label: t('NotificationProvidersPage.empty.addFirst'), onClick: openCreate, icon: Plus } : undefined}
            />
          </CardContent>
        </Card>
      ) : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/30">
                  <th className="px-4 py-3 w-10">
                    <Checkbox
                      checked={
                        filteredProviders.length > 0 &&
                        filteredProviders.every((p) => selectedIds.has(p.id))
                      }
                      onCheckedChange={(v) => {
                        if (v) setSelectedProviders([...filteredProviders]);
                        else setSelectedProviders([]);
                      }}
                      aria-label={t('common:DataTable.selectAllRows')}
                    />
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-muted-foreground">
                    <button type="button" onClick={() => handleSort('name')} className="flex items-center gap-1 hover:text-foreground transition-colors">
                      {t('NotificationProvidersPage.table.provider')} <ArrowUpDown className="h-3 w-3" />
                    </button>
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-muted-foreground">
                    <button type="button" onClick={() => handleSort('channel')} className="flex items-center gap-1 hover:text-foreground transition-colors">
                      {t('NotificationProvidersPage.table.channel')} <ArrowUpDown className="h-3 w-3" />
                    </button>
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-muted-foreground">{t('NotificationProvidersPage.table.status')}</th>
                  <th className="text-left px-4 py-3 font-medium text-muted-foreground">{t('NotificationProvidersPage.table.lastVerified')}</th>
                  <th className="text-left px-4 py-3 font-medium text-muted-foreground">{t('NotificationProvidersPage.table.rateLimits')}</th>
                  <th className="text-left px-4 py-3 font-medium text-muted-foreground">
                    <button type="button" onClick={() => handleSort('created_at')} className="flex items-center gap-1 hover:text-foreground transition-colors">
                      {t('NotificationProvidersPage.table.created')} <ArrowUpDown className="h-3 w-3" />
                    </button>
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-muted-foreground w-20">{t('NotificationProvidersPage.table.enabled')}</th>
                  <th className="px-4 py-3 w-12" />
                </tr>
              </thead>
              <tbody>
                <AnimatePresence mode="popLayout">
                  {filteredProviders.map((p) => (
                    <ProviderRow
                      key={p.id}
                      provider={p}
                      types={providerTypes}
                      selected={selectedIds.has(p.id)}
                      onSelectChange={(checked) => toggleRowSelection(p, checked)}
                      onEdit={() => openEdit(p)}
                      onDelete={() => setDeleteTarget(p)}
                      onToggle={(v) => toggleMut.mutate({ id: p.id, enabled: v })}
                      onVerify={() => handleVerify(p.id)}
                      onTest={() => handleTest(p)}
                      onSetDefault={() => setDefaultMut.mutate(p.id)}
                      isVerifying={verifyingId === p.id}
                    />
                  ))}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Bulk Actions */}
      <BulkActionsBar
        selectedCount={selectedProviders.length}
        itemName="provider"
        onClear={() => setSelectedProviders([])}
        actions={[
          {
            // ``Verify`` is the no-recipient connectivity check
            // (``POST /providers/{id}/verify``); ``Test`` would be the
            // send-a-real-message path (``POST /providers/{id}/test``) and
            // requires a recipient. The bulk action below is connectivity
            // only, relabeling so the UI matches what we actually call.
            label: t('NotificationProvidersPage.bulk.verify'),
            icon: Send,
            onClick: () => {
              selectedProviders.forEach((p) => {
                if (p.is_enabled) handleVerify(p.id);
              });
              setSelectedProviders([]);
            },
          },
          {
            label: t('NotificationProvidersPage.bulk.disable'),
            icon: Power,
            onClick: () => {
              selectedProviders.forEach((p) => {
                if (p.is_enabled) toggleMut.mutate({ id: p.id, enabled: false });
              });
              setSelectedProviders([]);
            },
          },
          {
            label: t('NotificationProvidersPage.bulk.delete'),
            icon: Trash2,
            variant: 'destructive',
            onClick: () => {
              if (confirm(t('NotificationProvidersPage.bulk.confirmDelete', { count: selectedProviders.length }))) {
                selectedProviders.forEach((p) => deleteMut.mutate(p.id));
                setSelectedProviders([]);
              }
            },
          },
        ]}
      />

      {/* Form dialog */}
      <ProviderFormDialog
        open={formOpen}
        onOpenChange={(v) => { setFormOpen(v); if (!v) setEditingProvider(null); }}
        providerTypes={providerTypes}
        existingProvider={editingProvider}
        onSubmit={handleFormSubmit}
        isSubmitting={createMut.isPending || updateMut.isPending}
      />

      {/* Delete confirmation */}
      <Dialog open={!!deleteTarget} onOpenChange={(v) => !v && setDeleteTarget(null)}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>{t('NotificationProvidersPage.deleteDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('NotificationProvidersPage.deleteDialog.confirm', { name: deleteTarget?.name ?? '' })}{' '}
              {t('NotificationProvidersPage.deleteDialog.warning')}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>{t('NotificationProvidersPage.common.cancel')}</Button>
            <Button
              variant="destructive"
              onClick={() => deleteTarget && deleteMut.mutate(deleteTarget.id)}
              disabled={deleteMut.isPending}
            >
              {deleteMut.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Trash2 className="mr-2 h-4 w-4" />}
              {t('NotificationProvidersPage.common.delete')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Tab 2 · Testing Console
// ═══════════════════════════════════════════════════════════════════

function TestingTab() {
  const { t } = useTranslation('enterprise');
  const { data: providers = [] } = useProviders();

  const [selectedProviderId, setSelectedProviderId] = useState<string>('');
  const [recipient, setRecipient] = useState('');
  const [testLog, setTestLog] = useState<TestLogEntry[]>([]);
  const [isTesting, setIsTesting] = useState(false);
  const [bulkChannel, setBulkChannel] = useState<string>('');
  const [isBulkTesting, setIsBulkTesting] = useState(false);

  // Read provider from URL search params (when navigating from providers tab)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const pid = params.get('provider');
    if (pid && providers.some((p) => p.id === pid)) {
      setSelectedProviderId(pid);
    }
  }, [providers]);

  const selectedProvider = providers.find((p) => p.id === selectedProviderId);
  const enabledProviders = useMemo(() => providers.filter((p) => p.is_enabled), [providers]);
  const allChannels = useMemo(() => Array.from(new Set(providers.map((p) => p.channel))), [providers]);

  const recipientPlaceholder = useMemo(() => {
    if (!selectedProvider) return t('NotificationProvidersPage.testing.selectProviderFirst');
    const ch = selectedProvider.channel;
    if (ch === 'email') return 'admin@example.com';
    if (ch === 'sms' || ch === 'whatsapp') return '+15551234567';
    if (ch === 'slack') return '#general';
    return 'https://your-endpoint.com/hook';
  }, [selectedProvider, t]);

  const addLogEntry = (entry: Omit<TestLogEntry, 'id' | 'timestamp'>) => {
    setTestLog((prev) => [{
      ...entry,
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: new Date(),
    }, ...prev]);
  };

  const runTest = async () => {
    if (!selectedProvider || !recipient) return;
    setIsTesting(true);
    const start = performance.now();
    try {
      const resp = await notificationApi.testProvider(selectedProvider.id, recipient);
      const data = resp.data;
      addLogEntry({
        providerId: selectedProvider.id,
        providerName: selectedProvider.name,
        channel: selectedProvider.channel,
        recipient,
        success: data.success,
        message: data.message,
        details: data.details || undefined,
        durationMs: Math.round(performance.now() - start),
      });
    } catch (err: unknown) {
      addLogEntry({
        providerId: selectedProvider.id,
        providerName: selectedProvider.name,
        channel: selectedProvider.channel,
        recipient,
        success: false,
        message: getApiErrorMessage(err, t('NotificationProvidersPage.testing.testFailed')),
        details: undefined,
        durationMs: Math.round(performance.now() - start),
      });
    } finally {
      setIsTesting(false);
    }
  };

  const runBulkTest = async () => {
    if (!bulkChannel || !recipient) return;
    setIsBulkTesting(true);
    const channelProviders = enabledProviders.filter((p) => p.channel === bulkChannel);
    for (const p of channelProviders) {
      const start = performance.now();
      try {
        const resp = await notificationApi.testProvider(p.id, recipient);
        const data = resp.data;
        addLogEntry({
          providerId: p.id,
          providerName: p.name,
          channel: p.channel,
          recipient,
          success: data.success,
          message: data.message,
          details: data.details || undefined,
          durationMs: Math.round(performance.now() - start),
        });
      } catch (err: unknown) {
        addLogEntry({
          providerId: p.id,
          providerName: p.name,
          channel: p.channel,
          recipient,
          success: false,
          message: getApiErrorMessage(err, t('NotificationProvidersPage.testing.testFailed')),
          details: undefined,
          durationMs: Math.round(performance.now() - start),
        });
      }
    }
    setIsBulkTesting(false);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Left · Test Form */}
      <div className="lg:col-span-1 space-y-6">
        {/* Single Test */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Send className="h-4 w-4" /> {t('NotificationProvidersPage.testing.singleTitle')}
            </CardTitle>
            <CardDescription>{t('NotificationProvidersPage.testing.singleDesc')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label className="text-xs">{t('NotificationProvidersPage.testing.providerLabel')}</Label>
              <Select value={selectedProviderId} onValueChange={setSelectedProviderId}>
                <SelectTrigger>
                  <SelectValue placeholder={t('NotificationProvidersPage.testing.selectProvider')} />
                </SelectTrigger>
                <SelectContent>
                  {enabledProviders.map((p) => {
                    const c = channelColor(p.channel);
                    return (
                      <SelectItem key={p.id} value={p.id}>
                        <span className="flex items-center gap-2">
                          <ChannelIcon channel={p.channel} className={cn('h-3.5 w-3.5', c.text)} />
                          {p.name}
                          <span className="text-muted-foreground text-xs">({p.channel})</span>
                        </span>
                      </SelectItem>
                    );
                  })}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label className="text-xs">{t('NotificationProvidersPage.testing.recipientLabel')}</Label>
              <Input
                value={recipient}
                onChange={(e) => setRecipient(e.target.value)}
                placeholder={recipientPlaceholder}
                disabled={!selectedProvider}
              />
            </div>

            <Button
              onClick={runTest}
              disabled={!selectedProvider || !recipient || isTesting}
              className="w-full"
            >
              {isTesting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Play className="mr-2 h-4 w-4" />}
              {t('NotificationProvidersPage.testing.sendTest')}
            </Button>
          </CardContent>
        </Card>

        {/* Bulk Test */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Zap className="h-4 w-4" /> {t('NotificationProvidersPage.testing.bulkTitle')}
            </CardTitle>
            <CardDescription>{t('NotificationProvidersPage.testing.bulkDesc')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label className="text-xs">{t('NotificationProvidersPage.testing.channelLabel')}</Label>
              <Select value={bulkChannel} onValueChange={setBulkChannel}>
                <SelectTrigger>
                  <SelectValue placeholder={t('NotificationProvidersPage.testing.selectChannel')} />
                </SelectTrigger>
                <SelectContent>
                  {allChannels.map((ch) => (
                    <SelectItem key={ch} value={ch} className="capitalize">
                      <span className="flex items-center gap-2">
                        <ChannelIcon channel={ch} className="h-3.5 w-3.5" />
                        {t('NotificationProvidersPage.testing.channelOption', { channel: ch, count: enabledProviders.filter((p) => p.channel === ch).length })}
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label className="text-xs">{t('NotificationProvidersPage.testing.recipientLabel')}</Label>
              <Input
                value={recipient}
                onChange={(e) => setRecipient(e.target.value)}
                placeholder={t('NotificationProvidersPage.testing.recipientAllPlaceholder')}
                disabled={!bulkChannel}
              />
            </div>

            <Button
              onClick={runBulkTest}
              disabled={!bulkChannel || !recipient || isBulkTesting}
              variant="secondary"
              className="w-full"
            >
              {isBulkTesting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Zap className="mr-2 h-4 w-4" />}
              {bulkChannel
                ? t('NotificationProvidersPage.testing.testAllChannel', { channel: bulkChannel })
                : t('NotificationProvidersPage.testing.testAll')}
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Right · Test Log */}
      <div className="lg:col-span-2">
        <Card className="h-full">
          <CardHeader className="pb-3 flex flex-row items-center justify-between">
            <div>
              <CardTitle className="text-base flex items-center gap-2">
                <Bug className="h-4 w-4" /> {t('NotificationProvidersPage.testing.resultsTitle')}
              </CardTitle>
              <CardDescription>{t('NotificationProvidersPage.testing.resultsDesc')}</CardDescription>
            </div>
            {testLog.length > 0 && (
              <Button variant="ghost" size="sm" onClick={() => setTestLog([])}>
                {t('NotificationProvidersPage.testing.clearLog')}
              </Button>
            )}
          </CardHeader>
          <CardContent>
            {testLog.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-center">
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted mb-3">
                  <Bug className="h-6 w-6 text-muted-foreground" />
                </div>
                <p className="text-sm text-muted-foreground">{t('NotificationProvidersPage.testing.emptyResults')}</p>
              </div>
            ) : (
              <div className="space-y-3 max-h-[600px] overflow-y-auto pr-1">
                <AnimatePresence initial={false}>
                  {testLog.map((entry) => (
                    <TestLogCard key={entry.id} entry={entry} />
                  ))}
                </AnimatePresence>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function TestLogCard({ entry }: { entry: TestLogEntry }) {
  const { t } = useTranslation('enterprise');
  const [expanded, setExpanded] = useState(false);
  const c = channelColor(entry.channel);

  return (
    <motion.div
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ duration: 0.2 }}
    >
      <div className={cn(
        'rounded-lg border p-3 space-y-2',
        entry.success
          ? 'border-emerald-500/30 bg-emerald-500/5'
          : 'border-destructive/30 bg-destructive/5',
      )}>
        {/* Header */}
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            {entry.success ? (
              <CheckCircle className="h-4 w-4 text-emerald-500 shrink-0" />
            ) : (
              <XCircle className="h-4 w-4 text-destructive shrink-0" />
            )}
            <span className="text-sm font-medium truncate">{entry.providerName}</span>
            <Badge className={cn('text-[10px] shrink-0', c.badge)} variant="outline">
              {entry.channel}
            </Badge>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-xs text-muted-foreground tabular-nums">{entry.durationMs}ms</span>
            <span className="text-xs text-muted-foreground">
              {format(entry.timestamp, 'HH:mm:ss')}
            </span>
          </div>
        </div>

        {/* Message */}
        <p className="text-xs text-muted-foreground">{entry.message}</p>
        <p className="text-xs text-muted-foreground">{t('NotificationProvidersPage.testing.toLabel')} <code className="font-mono">{entry.recipient}</code></p>

        {/* Expandable details */}
        {entry.details && Object.keys(entry.details).length > 0 && (
          <div>
            <button
              type="button"
              onClick={() => setExpanded(!expanded)}
              className="text-xs text-primary hover:underline flex items-center gap-1"
            >
              <ChevronDown className={cn('h-3 w-3 transition-transform', expanded && 'rotate-180')} />
              {expanded ? t('NotificationProvidersPage.testing.hideDebug') : t('NotificationProvidersPage.testing.showDebug')}
            </button>
            {expanded && (
              <motion.pre
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                className="mt-2 rounded-md bg-muted/50 p-2 text-xs font-mono overflow-x-auto max-h-48"
              >
                {JSON.stringify(entry.details, null, 2)}
              </motion.pre>
            )}
          </div>
        )}
      </div>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Tab 3 · Health & Diagnostics
// ═══════════════════════════════════════════════════════════════════

function HealthTab() {
  const { t } = useTranslation('enterprise');
  const queryClient = useQueryClient();
  const { data: providers = [], isLoading } = useProviders();
  const { data: providerTypes = [] } = useProviderTypes();
  const [verifyingAll, setVerifyingAll] = useState(false);
  const [verifyResults, setVerifyResults] = useState<Record<string, { success: boolean; message: string }>>({});
  const [expandedConfigs, setExpandedConfigs] = useState<Set<string>>(new Set());

  const toggleConfig = (id: string) => {
    setExpandedConfigs((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const verifyAll = async () => {
    setVerifyingAll(true);
    setVerifyResults({});
    for (const p of providers.filter((p) => p.is_enabled)) {
      try {
        const resp = await notificationApi.verifyProvider(p.id);
        setVerifyResults((prev) => ({ ...prev, [p.id]: { success: resp.data.success, message: resp.data.message } }));
      } catch (err: unknown) {
        setVerifyResults((prev) => ({ ...prev, [p.id]: { success: false, message: getApiErrorMessage(err, t('NotificationProvidersPage.health.verifyFailed')) } }));
      }
    }
    setVerifyingAll(false);
    queryClient.invalidateQueries({ queryKey: ['notification-providers'] });
  };

  // Channel readiness
  const channelReadiness = useMemo(() => {
    const allChannels = Array.from(new Set(providerTypes.map((t) => t.channel)));
    return allChannels.map((ch) => {
      const chProviders = providers.filter((p) => p.channel === ch);
      const enabled = chProviders.filter((p) => p.is_enabled);
      const verified = enabled.filter((p) => p.is_verified);
      const hasDefault = enabled.some((p) => p.is_default);
      const hasError = enabled.some((p) => p.last_error);

      let status: 'ready' | 'warning' | 'error' | 'unconfigured';
      if (enabled.length === 0) status = 'unconfigured';
      else if (verified.length > 0 && hasDefault && !hasError) status = 'ready';
      else if (verified.length > 0) status = 'warning';
      else status = 'error';

      return { channel: ch, status, total: chProviders.length, enabled: enabled.length, verified: verified.length, hasDefault, hasError };
    });
  }, [providers, providerTypes]);

  const enabledProviders = useMemo(() => providers.filter((p) => p.is_enabled), [providers]);

  if (isLoading) {
    return <Skeleton className="h-96 w-full" />;
  }

  return (
    <div className="space-y-6">
      {/* Verify All Bar */}
      <Card>
        <CardContent noOffset className="flex items-center justify-between gap-4 py-4">
          <div className="space-y-0.5">
            <h3 className="text-sm font-semibold">{t('NotificationProvidersPage.health.connectivityCheck')}</h3>
            <p className="text-xs text-muted-foreground">
              {t('NotificationProvidersPage.health.connectivityDesc')}
              {enabledProviders.length > 0 && ` ${t('NotificationProvidersPage.health.providersToCheck', { count: enabledProviders.length })}`}
            </p>
          </div>
          <Button onClick={verifyAll} disabled={verifyingAll || enabledProviders.length === 0} size="sm">
            {verifyingAll ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
            {t('NotificationProvidersPage.health.verifyAll', { count: enabledProviders.length })}
          </Button>
        </CardContent>
      </Card>

      {/* Channel Readiness Matrix */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">{t('NotificationProvidersPage.health.channelReadiness')}</CardTitle>
          <CardDescription>{t('NotificationProvidersPage.health.channelReadinessDesc')}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {channelReadiness.map(({ channel, status, enabled, verified, hasDefault }) => {
              const c = channelColor(channel);
              const statusIcon = status === 'ready'
                ? <CheckCircle className="h-4 w-4 text-emerald-500" />
                : status === 'warning'
                ? <AlertTriangle className="h-4 w-4 text-amber-500" />
                : status === 'error'
                ? <XCircle className="h-4 w-4 text-destructive" />
                : <Power className="h-4 w-4 text-muted-foreground" />;
              const statusLabel = status === 'ready' ? t('NotificationProvidersPage.health.statusReady') : status === 'warning' ? t('NotificationProvidersPage.health.statusPartial') : status === 'error' ? t('NotificationProvidersPage.health.statusFailing') : t('NotificationProvidersPage.health.statusNotConfigured');

              return (
                <div key={channel} className={cn(
                  'flex flex-col items-center gap-2 rounded-lg border p-4 text-center',
                  status === 'ready' && 'border-emerald-500/20 bg-emerald-500/5',
                  status === 'warning' && 'border-amber-500/20 bg-amber-500/5',
                  status === 'error' && 'border-destructive/20 bg-destructive/5',
                  status === 'unconfigured' && 'border-muted',
                )}>
                  <ChannelIcon channel={channel} className={cn('h-5 w-5', c.text)} />
                  <p className="text-sm font-medium capitalize">{channel}</p>
                  <div className="flex items-center gap-1">
                    {statusIcon}
                    <span className="text-xs">{statusLabel}</span>
                  </div>
                  <div className="text-[10px] text-muted-foreground space-y-0.5">
                    <p>{t('NotificationProvidersPage.health.enabledVerified', { enabled, verified })}</p>
                    <p>{hasDefault ? t('NotificationProvidersPage.dashboard.defaultSet') : t('NotificationProvidersPage.dashboard.noDefault')}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Per-Provider Health Cards */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold">{t('NotificationProvidersPage.health.healthDetails')}</h3>
          <Badge variant="secondary" className="text-xs">{t('NotificationProvidersPage.health.providersCount', { count: providers.length })}</Badge>
        </div>

        {providers.length === 0 ? (
          <Card>
            <CardContent noOffset className="py-12 text-center text-muted-foreground">
              {t('NotificationProvidersPage.health.noProviders')}
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            {providers.map((p) => {
              const c = channelColor(p.channel);
              const vr = verifyResults[p.id];
              const configExpanded = expandedConfigs.has(p.id);
              const createdAt = p.created_at && isValid(new Date(p.created_at)) ? format(new Date(p.created_at), 'MMM d, yyyy HH:mm') : '-';
              const updatedAt = p.updated_at && isValid(new Date(p.updated_at)) ? formatDistanceToNow(new Date(p.updated_at), { addSuffix: true }) : '-';
              const lastVerifiedAt = p.last_verified_at && isValid(new Date(p.last_verified_at))
                ? format(new Date(p.last_verified_at), 'MMM d, yyyy HH:mm')
                : t('NotificationProvidersPage.health.neverCapitalized');

              return (
                <Card key={p.id} className={cn('overflow-hidden', !p.is_enabled && 'opacity-50')}>
                  <CardContent noOffset className="p-4 space-y-3">
                    {/* Header */}
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className={cn('flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border', c.bg, c.border)}>
                          <ChannelIcon channel={p.channel} className={cn('h-4 w-4', c.text)} />
                        </div>
                        <div className="min-w-0">
                          <h4 className="text-sm font-medium truncate">{p.name}</h4>
                          <p className="text-xs text-muted-foreground">{providerTypeLabel(p.provider_type, providerTypes)}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        {p.is_default && <Badge variant="secondary" className="text-[9px]">{t('NotificationProvidersPage.common.default')}</Badge>}
                        {p.is_enabled ? (
                          <Badge variant="outline" className="text-[9px] text-emerald-600">{t('NotificationProvidersPage.health.on')}</Badge>
                        ) : (
                          <Badge variant="outline" className="text-[9px] text-muted-foreground">{t('NotificationProvidersPage.health.off')}</Badge>
                        )}
                      </div>
                    </div>

                    {/* Health info grid */}
                    <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                      <div className="text-muted-foreground">{t('NotificationProvidersPage.health.verifiedLabel')}</div>
                      <div className="font-medium flex items-center gap-1">
                        {p.is_verified ? (
                          <><CheckCircle className="h-3 w-3 text-emerald-500" /> {t('NotificationProvidersPage.common.yes')}</>
                        ) : (
                          <><XCircle className="h-3 w-3 text-amber-500" /> {t('NotificationProvidersPage.common.no')}</>
                        )}
                      </div>
                      <div className="text-muted-foreground">{t('NotificationProvidersPage.health.lastVerifiedLabel')}</div>
                      <div className="font-medium">{lastVerifiedAt}</div>
                      <div className="text-muted-foreground">{t('NotificationProvidersPage.health.rateLimitsLabel')}</div>
                      <div className="font-medium">{(p.rate_limit_per_hour ?? 0).toLocaleString()}/h · {(p.rate_limit_per_day ?? 0).toLocaleString()}/d</div>
                      <div className="text-muted-foreground">{t('NotificationProvidersPage.health.createdLabel')}</div>
                      <div className="font-medium">{createdAt}</div>
                      <div className="text-muted-foreground">{t('NotificationProvidersPage.health.updatedLabel')}</div>
                      <div className="font-medium">{updatedAt}</div>
                    </div>

                    {/* Error */}
                    {p.last_error && (
                      <div className="flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/5 p-2">
                        <XCircle className="h-4 w-4 text-destructive shrink-0 mt-0.5" />
                        <p className="text-xs text-destructive break-all">{p.last_error}</p>
                      </div>
                    )}

                    {/* Verify result (from bulk verify) */}
                    {vr && (
                      <div className={cn(
                        'flex items-center gap-2 rounded-md border p-2 text-xs',
                        vr.success
                          ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-700 dark:text-emerald-400'
                          : 'border-destructive/30 bg-destructive/5 text-destructive',
                      )}>
                        {vr.success ? <CheckCircle className="h-3.5 w-3.5 shrink-0" /> : <XCircle className="h-3.5 w-3.5 shrink-0" />}
                        {vr.message}
                      </div>
                    )}

                    {/* Config audit (expandable) */}
                    <div>
                      <button
                        type="button"
                        onClick={() => toggleConfig(p.id)}
                        className="text-xs text-primary hover:underline flex items-center gap-1"
                      >
                        {configExpanded ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                        {configExpanded ? t('NotificationProvidersPage.health.hideConfig') : t('NotificationProvidersPage.health.viewConfig')}
                      </button>
                      {configExpanded && (
                        <pre className="mt-2 rounded-md bg-muted/50 p-2 text-xs font-mono overflow-x-auto max-h-36">
                          {JSON.stringify(p.config_summary, null, 2)}
                        </pre>
                      )}
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Main Page Component
// ═══════════════════════════════════════════════════════════════════

export function NotificationProvidersPage() {
  const { t } = useTranslation('enterprise');
  const { tab } = useParams<{ tab?: string }>();
  const navigate = useNavigate();
  const { data: providers = [], isError: providersError } = useProviders();

  const activeTab: PageTab = PAGE_TABS.includes(tab as PageTab) ? (tab as PageTab) : 'providers';

  const handleTabChange = (value: string) => {
    navigate(`/notification-providers/${value}`, { replace: true });
  };

  // Stats for header
  const stats = useMemo(() => {
    const enabled = providers.filter((p) => p.is_enabled);
    const verified = providers.filter((p) => p.is_verified);
    const errors = providers.filter((p) => p.last_error && p.is_enabled);
    return [
      { title: t('NotificationProvidersPage.stats.total'), value: providers.length, icon: Zap },
      { title: t('NotificationProvidersPage.stats.enabled'), value: `${enabled.length} / ${providers.length}`, icon: Power },
      { title: t('NotificationProvidersPage.stats.verified'), value: `${verified.length} / ${providers.length}`, icon: ShieldCheck },
      { title: t('NotificationProvidersPage.stats.errors'), value: errors.length, icon: AlertTriangle, ...(errors.length > 0 ? { description: t('NotificationProvidersPage.stats.needsAttention') } : {}) },
    ];
  }, [providers, t]);

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Zap}
        title={t('NotificationProvidersPage.header.title')}
        subtitle={t('NotificationProvidersPage.header.subtitle')}
        actions={
          <Button size="sm" onClick={() => navigate('/notification-providers/providers')}>
            <Plus className="mr-2 h-4 w-4" /> {t('NotificationProvidersPage.toolbar.addProvider')}
          </Button>
        }
      />

      {providersError && (
        <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
          {t('NotificationProvidersPage.header.loadError')}
        </div>
      )}

      <StatsGrid stats={stats} columns={4} />

      <Tabs value={activeTab} onValueChange={handleTabChange}>
        <TabsList>
          {PAGE_TABS.map((tabKey) => {
            const meta = TAB_META[tabKey];
            return (
              <TabsTrigger key={tabKey} value={tabKey} className="flex items-center gap-1.5">
                <meta.icon className="h-3.5 w-3.5" />
                {t(`NotificationProvidersPage.${meta.labelKey}`)}
              </TabsTrigger>
            );
          })}
        </TabsList>

        <TabsContent value="providers" className="mt-6">
          <ProvidersTab />
        </TabsContent>

        <TabsContent value="testing" className="mt-6">
          <TestingTab />
        </TabsContent>

        <TabsContent value="health" className="mt-6">
          <HealthTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

export default NotificationProvidersPage;
