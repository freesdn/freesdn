// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Enterprise WiFi Networks Management
 *
 * Full-featured SSID management: list, create, edit, toggle, delete,
 * detail view with tabbed settings, security info, band badges, etc.
 */

import { useState, useMemo, useCallback, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { useSearchParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import {
  RefreshCw,
  Plus,
  Pencil,
  Trash2,
  Wifi,
  WifiOff,
  MoreHorizontal,
  Eye,
  EyeOff,
  Lock,
  Shield,
  Users,
  Signal,
  Power,
  PowerOff,
  Radio,
  Globe,
  ChevronRight,
  ArrowLeft,
  Settings2,
  Clock,
  Filter as FilterIcon,
  ShieldCheck,
  Zap,
  Network,
  Check,
  X,
  Download,
} from 'lucide-react';
import { DataTable, DataTableColumn } from '@/components/ui/data-table';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { SearchBar } from '@/components/ui/search-bar';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import {
  networkApi,
  WifiNetwork,
  WifiNetworkCreate,
  WifiNetworkUpdate,
} from '@/lib/api';
import { cn } from '@/lib/utils';
import { PageHeader, PageToolbar } from '@/components/layout';
import { CapabilityMaturityBadge } from '@/components/ui/capability-maturity-badge';
import { StatsGrid } from '@/components/ui/stats-grid';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import { useToast } from '@/hooks/use-toast';

// ─── Helpers ────────────────────────────────────────────────────────

// `labelKey` is a suffix under WifiNetworksPage.security.modes.* (translated at
// the use site). `short` values are technical acronyms, kept verbatim. `color`
// is a className.
const SECURITY_CONFIG: Record<
  string,
  { labelKey: string; short: string; color: string }
> = {
  open: {
    labelKey: 'open',
    short: 'Open',
    color: 'bg-destructive/10 text-destructive border-destructive/20',
  },
  wpa2_personal: {
    labelKey: 'wpa2Personal',
    short: 'WPA2',
    color: 'bg-info/10 text-info border-info/20',
  },
  wpa3_personal: {
    labelKey: 'wpa3Personal',
    short: 'WPA3',
    color: 'bg-success/10 text-success border-success/20',
  },
  wpa2_enterprise: {
    labelKey: 'wpa2Enterprise',
    short: 'WPA2-E',
    color: 'bg-primary/10 text-primary border-primary/20',
  },
  wpa3_enterprise: {
    labelKey: 'wpa3Enterprise',
    short: 'WPA3-E',
    color: 'bg-primary/10 text-primary border-primary/20',
  },
  wpa_wpa2_personal: {
    labelKey: 'wpaWpa2Mixed',
    short: 'WPA/WPA2',
    color: 'bg-warning/10 text-warning border-warning/20',
  },
  wpa2_wpa3_personal: {
    labelKey: 'wpa2Wpa3Mixed',
    short: 'WPA2/WPA3',
    color: 'bg-info/10 text-info border-info/20',
  },
};

function getSecurityInfo(sec: string, t: TFunction) {
  const cfg = SECURITY_CONFIG[sec];
  if (cfg) {
    return {
      label: t(`WifiNetworksPage.security.modes.${cfg.labelKey}`),
      short: cfg.short,
      color: cfg.color,
    };
  }
  return {
    label: sec.replace(/_/g, ' ').toUpperCase(),
    short: sec.toUpperCase(),
    color: 'bg-muted text-muted-foreground border-muted',
  };
}

function bandLabel(band: string) {
  switch (band) {
    case '2.4ghz':
      return '2.4 GHz';
    case '5ghz':
      return '5 GHz';
    case '6ghz':
      return '6 GHz';
    case 'all':
      return '2.4 / 5 GHz';
    case 'both':
    default:
      return '2.4 / 5 GHz';
  }
}

// Rate limits are stored/transported in kbps (backend model + Omada sync),
// but the UI presents them to operators in Mbps. Convert at the boundary.
function kbpsToMbps(kbps: number | null | undefined): number | '' {
  if (kbps === null || kbps === undefined) return '';
  return kbps / 1000;
}

function mbpsToKbps(mbps: string): number | undefined {
  if (!mbps) return undefined;
  const parsed = parseFloat(mbps);
  if (Number.isNaN(parsed)) return undefined;
  return Math.round(parsed * 1000);
}

// ─── Badge / Pill Components ────────────────────────────────────────

function WifiStatusBadge({ enabled }: { enabled: boolean }) {
  const { t } = useTranslation('network');
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium',
        enabled
          ? 'bg-success/10 text-success border-success/20'
          : 'bg-muted text-muted-foreground border-muted',
      )}
    >
      {enabled ? (
        <>
          <Wifi className="h-3 w-3" /> {t('WifiNetworksPage.status.active')}
        </>
      ) : (
        <>
          <WifiOff className="h-3 w-3" /> {t('WifiNetworksPage.status.disabled')}
        </>
      )}
    </span>
  );
}

function SecurityBadge({ security }: { security: string }) {
  const { t } = useTranslation('network');
  const info = getSecurityInfo(security, t);
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium',
        info.color,
      )}
    >
      <Lock className="h-3 w-3" />
      {info.short}
    </span>
  );
}

function BandBadge({ band }: { band: string }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-md bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
      <Signal className="h-3 w-3" />
      {bandLabel(band)}
    </span>
  );
}

function FeaturePill({
  icon: Icon,
  label,
  variant = 'default',
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  variant?: 'default' | 'warn' | 'info' | 'success';
}) {
  const colors = {
    default: 'bg-muted text-muted-foreground',
    warn: 'bg-warning/10 text-warning',
    info: 'bg-info/10 text-info',
    success: 'bg-success/10 text-success',
  };
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium',
        colors[variant],
      )}
    >
      <Icon className="h-3 w-3" />
      {label}
    </span>
  );
}

// (Stats migrated inline to canonical <StatsGrid /> in page body)

// ─── WiFi Form Dialog ───────────────────────────────────────────────

interface WifiFormDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  network?: WifiNetwork;
  onSubmit: (data: WifiNetworkCreate | WifiNetworkUpdate) => void;
  isLoading?: boolean;
}

function WifiFormDialog({
  open,
  onOpenChange,
  network,
  onSubmit,
  isLoading,
}: WifiFormDialogProps) {
  const { t } = useTranslation('network');
  const isEditing = !!network;
  const [showPassword, setShowPassword] = useState(false);

  const defaultData: WifiNetworkCreate = {
    ssid: network?.ssid || '',
    password: '',
    security: network?.security || 'wpa2_personal',
    vlan_id: network?.vlan_id,
    hidden: network?.hidden || false,
    enabled: network?.enabled ?? true,
    band: network?.band || 'both',
    client_isolation: network?.client_isolation || false,
    band_steering: network?.band_steering ?? false,
    fast_roaming: network?.fast_roaming ?? false,
    rate_limit_enabled: network?.rate_limit_enabled || false,
    rate_limit_up: network?.rate_limit_up,
    rate_limit_down: network?.rate_limit_down,
  };

  const [formData, setFormData] = useState<WifiNetworkCreate>(defaultData);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const submitData = { ...formData };
    if (isEditing && !submitData.password) {
      delete submitData.password;
    }
    onSubmit(submitData);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[640px] max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle>
            {isEditing
              ? t('WifiNetworksPage.form.editTitle')
              : t('WifiNetworksPage.form.createTitle')}
          </DialogTitle>
          <DialogDescription>
            {isEditing
              ? t('WifiNetworksPage.form.editDescription')
              : t('WifiNetworksPage.form.createDescription')}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="flex flex-col flex-1 overflow-hidden">
          <Tabs defaultValue="basic" className="flex-1 overflow-hidden flex flex-col">
            <TabsList className="w-full justify-start">
              <TabsTrigger value="basic">{t('WifiNetworksPage.form.tabs.basic')}</TabsTrigger>
              <TabsTrigger value="security">{t('WifiNetworksPage.form.tabs.security')}</TabsTrigger>
              <TabsTrigger value="advanced">{t('WifiNetworksPage.form.tabs.advanced')}</TabsTrigger>
              <TabsTrigger value="qos">{t('WifiNetworksPage.form.tabs.qos')}</TabsTrigger>
            </TabsList>

            <div className="flex-1 overflow-y-auto pr-1 mt-4">
              {/* ── Basic ───────────────────────────── */}
              <TabsContent value="basic" className="space-y-4 mt-0">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="ssid">{t('WifiNetworksPage.form.fields.ssid')}</Label>
                    <Input
                      id="ssid"
                      value={formData.ssid}
                      onChange={(e) =>
                        setFormData({ ...formData, ssid: e.target.value })
                      }
                      placeholder={t('WifiNetworksPage.form.placeholders.ssid')}
                      maxLength={32}
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="band">{t('WifiNetworksPage.form.fields.band')}</Label>
                    <Select
                      value={formData.band}
                      onValueChange={(v) =>
                        setFormData({ ...formData, band: v })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="both">{t('WifiNetworksPage.form.bandOptions.both')}</SelectItem>
                        <SelectItem value="2.4ghz">{t('WifiNetworksPage.form.bandOptions.band24')}</SelectItem>
                        <SelectItem value="5ghz">{t('WifiNetworksPage.form.bandOptions.band5')}</SelectItem>
                        <SelectItem value="all">{t('WifiNetworksPage.form.bandOptions.all')}</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="vlan_id">{t('WifiNetworksPage.form.fields.vlanId')}</Label>
                    <Input
                      id="vlan_id"
                      type="number"
                      min={1}
                      max={4094}
                      value={formData.vlan_id || ''}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          vlan_id: e.target.value
                            ? parseInt(e.target.value)
                            : undefined,
                        })
                      }
                      placeholder={t('WifiNetworksPage.form.placeholders.defaultVlan')}
                    />
                  </div>
                  <div className="flex items-end pb-1">
                    <div className="flex items-center justify-between rounded-lg border p-3 w-full">
                      <div className="space-y-0.5">
                        <Label className="text-sm">{t('WifiNetworksPage.form.fields.enabled')}</Label>
                      </div>
                      <Switch
                        checked={formData.enabled}
                        onCheckedChange={(c) =>
                          setFormData({ ...formData, enabled: c })
                        }
                      />
                    </div>
                  </div>
                </div>
              </TabsContent>

              {/* ── Security ─────────────────────────── */}
              <TabsContent value="security" className="space-y-4 mt-0">
                <div className="space-y-2">
                  <Label>{t('WifiNetworksPage.form.fields.securityMode')}</Label>
                  <Select
                    value={formData.security}
                    onValueChange={(v) =>
                      setFormData({ ...formData, security: v })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="wpa3_personal">{t('WifiNetworksPage.security.modes.wpa3Personal')}</SelectItem>
                      <SelectItem value="wpa2_wpa3_personal">
                        {t('WifiNetworksPage.security.modes.wpa2Wpa3Transition')}
                      </SelectItem>
                      <SelectItem value="wpa2_personal">{t('WifiNetworksPage.security.modes.wpa2Personal')}</SelectItem>
                      <SelectItem value="wpa3_enterprise">
                        {t('WifiNetworksPage.security.modes.wpa3Enterprise')}
                      </SelectItem>
                      <SelectItem value="wpa2_enterprise">
                        {t('WifiNetworksPage.security.modes.wpa2Enterprise')}
                      </SelectItem>
                      <SelectItem value="wpa_wpa2_personal">
                        {t('WifiNetworksPage.security.modes.wpaWpa2MixedLegacy')}
                      </SelectItem>
                      <SelectItem value="open">{t('WifiNetworksPage.security.modes.open')}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {formData.security !== 'open' &&
                  !formData.security?.includes('enterprise') && (
                    <div className="space-y-2">
                      <Label htmlFor="password">{t('WifiNetworksPage.form.fields.preSharedKey')}</Label>
                      <div className="relative">
                        <Input
                          id="password"
                          type={showPassword ? 'text' : 'password'}
                          value={formData.password}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              password: e.target.value,
                            })
                          }
                          placeholder={
                            isEditing
                              ? t('WifiNetworksPage.form.placeholders.unchanged')
                              : t('WifiNetworksPage.form.placeholders.minChars')
                          }
                          minLength={isEditing ? 0 : 8}
                          required={!isEditing}
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="absolute right-1 top-1 h-7 w-7 p-0"
                          onClick={() => setShowPassword(!showPassword)}
                        >
                          {showPassword ? (
                            <EyeOff className="h-4 w-4" />
                          ) : (
                            <Eye className="h-4 w-4" />
                          )}
                        </Button>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        {t('WifiNetworksPage.form.help.wpaPassword')}
                      </p>
                    </div>
                  )}

                <div className="flex items-center justify-between rounded-lg border p-3">
                  <div className="space-y-0.5">
                    <Label className="text-sm">{t('WifiNetworksPage.form.fields.hiddenNetwork')}</Label>
                    <p className="text-xs text-muted-foreground">
                      {t('WifiNetworksPage.form.help.hiddenNetwork')}
                    </p>
                  </div>
                  <Switch
                    checked={formData.hidden}
                    onCheckedChange={(c) =>
                      setFormData({ ...formData, hidden: c })
                    }
                  />
                </div>
              </TabsContent>

              {/* ── Advanced ─────────────────────────── */}
              <TabsContent value="advanced" className="space-y-4 mt-0">
                <div className="grid grid-cols-1 gap-3">
                  {[
                    {
                      key: 'client_isolation' as const,
                      label: t('WifiNetworksPage.form.advanced.clientIsolation.label'),
                      desc: t('WifiNetworksPage.form.advanced.clientIsolation.desc'),
                      icon: Users,
                    },
                    {
                      key: 'band_steering' as const,
                      label: t('WifiNetworksPage.form.advanced.bandSteering.label'),
                      desc: t('WifiNetworksPage.form.advanced.bandSteering.desc'),
                      icon: Radio,
                    },
                    {
                      key: 'fast_roaming' as const,
                      label: t('WifiNetworksPage.form.advanced.fastRoaming.label'),
                      desc: t('WifiNetworksPage.form.advanced.fastRoaming.desc'),
                      icon: Zap,
                    },
                  ].map((opt) => (
                    <div
                      key={opt.key}
                      className="flex items-center justify-between rounded-lg border p-3"
                    >
                      <div className="flex items-center gap-3">
                        <opt.icon className="h-4 w-4 text-muted-foreground" />
                        <div className="space-y-0.5">
                          <Label className="text-sm">{opt.label}</Label>
                          <p className="text-xs text-muted-foreground">
                            {opt.desc}
                          </p>
                        </div>
                      </div>
                      <Switch
                        checked={
                          formData[opt.key] as boolean | undefined
                        }
                        onCheckedChange={(c) =>
                          setFormData({ ...formData, [opt.key]: c })
                        }
                      />
                    </div>
                  ))}
                </div>
              </TabsContent>

              {/* ── QoS / Rate Limiting ──────────────── */}
              <TabsContent value="qos" className="space-y-4 mt-0">
                <div className="flex items-center justify-between rounded-lg border p-3">
                  <div className="space-y-0.5">
                    <Label className="text-sm">{t('WifiNetworksPage.form.qos.enableRateLimiting')}</Label>
                    <p className="text-xs text-muted-foreground">
                      {t('WifiNetworksPage.form.qos.capBandwidth')}
                    </p>
                  </div>
                  <Switch
                    checked={formData.rate_limit_enabled}
                    onCheckedChange={(c) =>
                      setFormData({ ...formData, rate_limit_enabled: c })
                    }
                  />
                </div>

                {formData.rate_limit_enabled && (
                  <div className="grid grid-cols-2 gap-4">
                    {/* Storage/wire unit is kbps (matches backend model +
                        Omada sync). Show the operator Mbps and convert on the
                        boundary: kbps→Mbps on display, Mbps→kbps on change. */}
                    <div className="space-y-2">
                      <Label>{t('WifiNetworksPage.form.qos.downloadLimit')}</Label>
                      <Input
                        type="number"
                        min={1}
                        value={kbpsToMbps(formData.rate_limit_down)}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            rate_limit_down: mbpsToKbps(e.target.value),
                          })
                        }
                        placeholder={t('WifiNetworksPage.form.placeholders.unlimited')}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>{t('WifiNetworksPage.form.qos.uploadLimit')}</Label>
                      <Input
                        type="number"
                        min={1}
                        value={kbpsToMbps(formData.rate_limit_up)}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            rate_limit_up: mbpsToKbps(e.target.value),
                          })
                        }
                        placeholder={t('WifiNetworksPage.form.placeholders.unlimited')}
                      />
                    </div>
                  </div>
                )}
              </TabsContent>
            </div>
          </Tabs>

          <DialogFooter className="mt-4 pt-4 border-t">
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              {t('WifiNetworksPage.actions.cancel')}
            </Button>
            <Button type="submit" disabled={isLoading}>
              {isLoading ? (
                <>
                  <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                  {isEditing
                    ? t('WifiNetworksPage.actions.saving')
                    : t('WifiNetworksPage.actions.creating')}
                </>
              ) : isEditing ? (
                t('WifiNetworksPage.actions.saveChanges')
              ) : (
                t('WifiNetworksPage.actions.createNetwork')
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ─── Detail / Edit Panel ────────────────────────────────────────────

function WifiDetailPanel({
  network,
  onClose,
  onEdit,
  onToggle,
}: {
  network: WifiNetwork;
  onClose: () => void;
  onEdit: () => void;
  onToggle: () => void;
}) {
  const { t } = useTranslation('network');
  const secInfo = getSecurityInfo(network.security, t);

  const features: { label: string; value: boolean; icon: React.ComponentType<{ className?: string }> }[] = [
    { label: t('WifiNetworksPage.features.clientIsolation'), value: network.client_isolation, icon: Users },
    { label: t('WifiNetworksPage.features.bandSteering'), value: network.band_steering, icon: Radio },
    { label: t('WifiNetworksPage.features.fastRoaming'), value: network.fast_roaming, icon: Zap },
    { label: t('WifiNetworksPage.features.hiddenSsid'), value: network.hidden, icon: EyeOff },
    { label: t('WifiNetworksPage.features.guestNetwork'), value: network.guest_network, icon: Globe },
    { label: t('WifiNetworksPage.features.rateLimiting'), value: network.rate_limit_enabled, icon: Shield },
    { label: t('WifiNetworksPage.features.macFiltering'), value: network.mac_filter_enabled, icon: FilterIcon },
    { label: t('WifiNetworksPage.features.captivePortal'), value: network.portal_enabled, icon: Globe },
    { label: t('WifiNetworksPage.features.schedule'), value: network.schedule_enabled, icon: Clock },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="icon" onClick={onClose}>
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <div
            className={cn(
              'flex h-12 w-12 items-center justify-center rounded-xl',
              network.enabled ? 'bg-success/10' : 'bg-muted',
            )}
          >
            {network.enabled ? (
              <Wifi className="h-6 w-6 text-success" />
            ) : (
              <WifiOff className="h-6 w-6 text-muted-foreground" />
            )}
          </div>
          <div>
            <h2 className="text-xl font-semibold flex items-center gap-2">
              {network.ssid}
              <WifiStatusBadge enabled={network.enabled} />
            </h2>
            <p className="text-sm text-muted-foreground">
              {network.wlan_group_name
                ? t('WifiNetworksPage.detail.wlanGroup', { name: network.wlan_group_name })
                : t('WifiNetworksPage.detail.wifiNetwork')}
              {network.external_id && (
                <span className="ml-2 text-xs opacity-60">
                  {t('WifiNetworksPage.detail.idLabel', { id: network.external_id })}
                </span>
              )}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={onToggle}>
            {network.enabled ? (
              <>
                <PowerOff className="mr-2 h-4 w-4" /> {t('WifiNetworksPage.actions.disable')}
              </>
            ) : (
              <>
                <Power className="mr-2 h-4 w-4" /> {t('WifiNetworksPage.actions.enable')}
              </>
            )}
          </Button>
          <Button size="sm" onClick={onEdit}>
            <Pencil className="mr-2 h-4 w-4" /> {t('WifiNetworksPage.actions.edit')}
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              {t('WifiNetworksPage.detail.cards.security')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-muted-foreground" />
              <span className="font-semibold text-sm">{secInfo.label}</span>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              {t('WifiNetworksPage.detail.cards.band')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <Signal className="h-4 w-4 text-muted-foreground" />
              <span className="font-semibold text-sm">
                {bandLabel(network.band)}
              </span>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              {t('WifiNetworksPage.detail.cards.vlan')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <Network className="h-4 w-4 text-muted-foreground" />
              <span className="font-semibold text-sm">
                {network.vlan_id
                  ? t('WifiNetworksPage.detail.vlanValue', { id: network.vlan_id })
                  : t('WifiNetworksPage.detail.defaultVlan')}
              </span>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              {t('WifiNetworksPage.detail.cards.type')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              {network.guest_network ? (
                <Globe className="h-4 w-4 text-info" />
              ) : (
                <Lock className="h-4 w-4 text-muted-foreground" />
              )}
              <span className="font-semibold text-sm">
                {network.guest_network
                  ? t('WifiNetworksPage.detail.typeGuest')
                  : t('WifiNetworksPage.detail.typePrivate')}
              </span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Features Grid */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t('WifiNetworksPage.detail.featuresTitle')}</CardTitle>
          <CardDescription>
            {t('WifiNetworksPage.detail.featuresDescription')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {features.map((f) => (
              <div
                key={f.label}
                className="flex items-center justify-between rounded-lg border px-3 py-2.5"
              >
                <div className="flex items-center gap-2 text-sm">
                  <f.icon className="h-4 w-4 text-muted-foreground" />
                  {f.label}
                </div>
                {f.value ? (
                  <Badge
                    variant="secondary"
                    className="bg-success/10 text-success border-success/20"
                  >
                    <Check className="h-3 w-3 mr-1" /> {t('WifiNetworksPage.toggle.on')}
                  </Badge>
                ) : (
                  <Badge
                    variant="secondary"
                    className="bg-muted text-muted-foreground border-muted"
                  >
                    <X className="h-3 w-3 mr-1" /> {t('WifiNetworksPage.toggle.off')}
                  </Badge>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Rate Limit detail */}
      {network.rate_limit_enabled && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t('WifiNetworksPage.detail.rateLimitingTitle')}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4">
              <div className="rounded-lg border p-3 text-center">
                <p className="text-xs text-muted-foreground mb-1">{t('WifiNetworksPage.detail.download')}</p>
                <p className="text-lg font-bold">
                  {network.rate_limit_down
                    ? t('WifiNetworksPage.detail.mbps', { value: kbpsToMbps(network.rate_limit_down) })
                    : t('WifiNetworksPage.detail.unlimited')}
                </p>
              </div>
              <div className="rounded-lg border p-3 text-center">
                <p className="text-xs text-muted-foreground mb-1">{t('WifiNetworksPage.detail.upload')}</p>
                <p className="text-lg font-bold">
                  {network.rate_limit_up
                    ? t('WifiNetworksPage.detail.mbps', { value: kbpsToMbps(network.rate_limit_up) })
                    : t('WifiNetworksPage.detail.unlimited')}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Main Page Component
// ═══════════════════════════════════════════════════════════════════

export default function WifiNetworksPage() {
  const { t } = useTranslation('network');
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // ── State ──────────────────────────────────────
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [bandFilter, setBandFilter] = useState<string>('all');
  const [searchParams, setSearchParams] = useSearchParams();
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editingNetwork, setEditingNetwork] = useState<WifiNetwork | undefined>();
  const [deletingNetwork, setDeletingNetwork] = useState<WifiNetwork | undefined>();
  const [selectedRows, setSelectedRows] = useState<WifiNetwork[]>([]);
  const [selectedNetworkId, setSelectedNetworkId] = useState<string | undefined>(
    searchParams.get('network') || undefined,
  );

  // URL ↔ state sync: ?network=<id>
  const selectNetwork = useCallback(
    (network: WifiNetwork | null | undefined) => {
      if (network) {
        setSelectedNetworkId(network.id);
        setSearchParams(
          (prev) => {
            prev.set('network', network.id);
            return prev;
          },
          { replace: true },
        );
      } else {
        setSelectedNetworkId(undefined);
        setSearchParams(
          (prev) => {
            prev.delete('network');
            return prev;
          },
          { replace: true },
        );
      }
    },
    [setSearchParams],
  );

  // Site context
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ── Queries / Mutations ────────────────────────
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['wifi-networks', { siteId: selectedSiteId }],
    queryFn: () => networkApi.wifi.list({ site_id: selectedSiteId ?? undefined, limit: 500 }),
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const onMutationError = (err: any) =>
    toast({
      title: t('common:error'),
      description: err?.response?.data?.detail || t('errors:internalServer'),
      variant: 'destructive',
    });

  const createMutation = useMutation({
    mutationFn: (d: WifiNetworkCreate) =>
      networkApi.wifi.create({ ...d, site_id: d.site_id ?? selectedSiteId ?? undefined }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['wifi-networks'] });
      setCreateDialogOpen(false);
    },
    onError: onMutationError,
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data: d }: { id: string; data: WifiNetworkUpdate }) =>
      networkApi.wifi.update(id, d),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['wifi-networks'] });
      setEditingNetwork(undefined);
    },
    onError: onMutationError,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => networkApi.wifi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['wifi-networks'] });
      setDeletingNetwork(undefined);
      if (selectedNetworkId === deletingNetwork?.id) {
        selectNetwork(undefined);
      }
    },
    onError: onMutationError,
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      networkApi.wifi.toggle(id, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['wifi-networks'] });
    },
    onError: onMutationError,
  });

  // ── Dedup: group by external_id ────────────────
  // Multiple controllers may sync the same SSID. Show unique SSIDs.
  const uniqueNetworks = useMemo(() => {
    const networks: WifiNetwork[] = data?.data?.items ?? [];
    const map = new Map<string, WifiNetwork>();
    for (const n of networks) {
      const key = n.external_id || n.id;
      if (!map.has(key)) map.set(key, n);
    }
    return Array.from(map.values());
  }, [data?.data?.items]);

  // Derive selected network from data (auto-refreshes after mutations)
  const selectedNetwork = useMemo(
    () =>
      selectedNetworkId
        ? uniqueNetworks.find((n) => n.id === selectedNetworkId)
        : undefined,
    [uniqueNetworks, selectedNetworkId],
  );

  // Resolve ?network=<id> from URL when data first loads
  const networkIdFromUrl = searchParams.get('network');
  useEffect(() => {
    if (!uniqueNetworks.length || !networkIdFromUrl) return;
    if (selectedNetworkId === networkIdFromUrl) return;
    const match = uniqueNetworks.find((n) => n.id === networkIdFromUrl);
    if (match) {
      setSelectedNetworkId(networkIdFromUrl);
    }
  }, [uniqueNetworks, networkIdFromUrl, selectedNetworkId]);

  // ── Filtering ──────────────────────────────────
  const filteredNetworks = useMemo(() => {
    return uniqueNetworks.filter((n) => {
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        if (
          !n.ssid.toLowerCase().includes(q) &&
          !(n.vlan_id && String(n.vlan_id).includes(q)) &&
          !(n.security && n.security.toLowerCase().includes(q))
        )
          return false;
      }
      if (statusFilter === 'active' && !n.enabled) return false;
      if (statusFilter === 'disabled' && n.enabled) return false;
      if (statusFilter === 'guest' && !n.guest_network) return false;
      if (bandFilter !== 'all' && n.band !== bandFilter) return false;
      return true;
    });
  }, [uniqueNetworks, searchQuery, statusFilter, bandFilter]);

  // ── Table Columns ──────────────────────────────
  const columns: DataTableColumn<WifiNetwork>[] = [
    {
      id: 'ssid',
      header: t('WifiNetworksPage.columns.network'),
      cell: (n: WifiNetwork) => (
        <button
          className="flex items-center gap-3 text-left group w-full"
          onClick={() => selectNetwork(n)}
        >
          <div
            className={cn(
              'flex h-9 w-9 items-center justify-center rounded-lg shrink-0',
              n.enabled ? 'bg-success/10' : 'bg-muted',
            )}
          >
            {n.enabled ? (
              <Wifi className="h-5 w-5 text-success" />
            ) : (
              <WifiOff className="h-5 w-5 text-muted-foreground" />
            )}
          </div>
          <div className="min-w-0">
            <div className="font-medium flex items-center gap-2 group-hover:text-primary transition-colors">
              {n.ssid}
              {n.hidden && (
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger>
                      <EyeOff className="h-3.5 w-3.5 text-muted-foreground" />
                    </TooltipTrigger>
                    <TooltipContent>{t('WifiNetworksPage.features.hiddenSsid')}</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              )}
              {n.guest_network && (
                <Badge
                  variant="outline"
                  className="text-[10px] px-1.5 py-0 h-4 bg-info/10 text-info border-info/20"
                >
                  {t('WifiNetworksPage.detail.typeGuest')}
                </Badge>
              )}
            </div>
            <div className="text-xs text-muted-foreground flex items-center gap-2">
              {n.vlan_id ? (
                <span>{t('WifiNetworksPage.detail.vlanValue', { id: n.vlan_id })}</span>
              ) : (
                <span>{t('WifiNetworksPage.form.placeholders.defaultVlan')}</span>
              )}
              {n.wlan_group_name && (
                <>
                  <span className="text-muted-foreground/40">·</span>
                  <span>{n.wlan_group_name}</span>
                </>
              )}
            </div>
          </div>
          <ChevronRight className="h-4 w-4 text-muted-foreground ml-auto opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
        </button>
      ),
    },
    {
      id: 'status',
      header: t('WifiNetworksPage.columns.status'),
      cell: (n: WifiNetwork) => <WifiStatusBadge enabled={n.enabled} />,
    },
    {
      id: 'security',
      header: t('WifiNetworksPage.columns.security'),
      cell: (n: WifiNetwork) => <SecurityBadge security={n.security} />,
    },
    {
      id: 'band',
      header: t('WifiNetworksPage.columns.band'),
      cell: (n: WifiNetwork) => <BandBadge band={n.band} />,
    },
    {
      id: 'features',
      header: t('WifiNetworksPage.columns.features'),
      cell: (n: WifiNetwork) => (
        <div className="flex flex-wrap gap-1">
          {n.client_isolation && (
            <FeaturePill icon={Users} label={t('WifiNetworksPage.pills.isolated')} variant="warn" />
          )}
          {n.fast_roaming && (
            <FeaturePill icon={Zap} label="802.11r" variant="info" />
          )}
          {n.band_steering && (
            <FeaturePill icon={Radio} label={t('WifiNetworksPage.pills.steering')} variant="info" />
          )}
          {n.rate_limit_enabled && (
            <FeaturePill
              icon={Shield}
              label={
                n.rate_limit_down || n.rate_limit_up
                  ? `${n.rate_limit_down ? kbpsToMbps(n.rate_limit_down) : '∞'}/${n.rate_limit_up ? kbpsToMbps(n.rate_limit_up) : '∞'}`
                  : t('WifiNetworksPage.pills.limited')
              }
              variant="default"
            />
          )}
          {n.guest_network && (
            <FeaturePill icon={Globe} label={t('WifiNetworksPage.detail.typeGuest')} variant="success" />
          )}
        </div>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: (n: WifiNetwork) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => selectNetwork(n)}>
              <Settings2 className="mr-2 h-4 w-4" />
              {t('WifiNetworksPage.actions.viewDetails')}
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() =>
                toggleMutation.mutate({
                  id: n.id,
                  enabled: !n.enabled,
                })
              }
            >
              {n.enabled ? (
                <>
                  <PowerOff className="mr-2 h-4 w-4" /> {t('WifiNetworksPage.actions.disable')}
                </>
              ) : (
                <>
                  <Power className="mr-2 h-4 w-4" /> {t('WifiNetworksPage.actions.enable')}
                </>
              )}
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => setEditingNetwork(n)}>
              <Pencil className="mr-2 h-4 w-4" /> {t('WifiNetworksPage.actions.edit')}
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => setDeletingNetwork(n)}
              className="text-destructive focus:text-destructive"
            >
              <Trash2 className="mr-2 h-4 w-4" /> {t('WifiNetworksPage.actions.delete')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ];

  const stats = useMemo(() => {
    const active = uniqueNetworks.filter((n) => n.enabled).length;
    const guest = uniqueNetworks.filter((n) => n.guest_network).length;
    const hidden = uniqueNetworks.filter((n) => n.hidden).length;
    return { total: uniqueNetworks.length, active, guest, hidden };
  }, [uniqueNetworks]);

  const hasActiveFilters =
    searchQuery !== '' || statusFilter !== 'all' || bandFilter !== 'all';

  // ── Export (client-side CSV from loaded rows) ──
  const handleExport = useCallback(() => {
    const rows = filteredNetworks;
    if (rows.length === 0) return;
    const headers = [
      'ssid',
      'enabled',
      'security',
      'band',
      'vlan_id',
      'hidden',
      'guest_network',
      'client_isolation',
      'band_steering',
      'fast_roaming',
      'rate_limit_enabled',
      'rate_limit_down',
      'rate_limit_up',
    ];
    const esc = (val: unknown) => {
      const s = val === undefined || val === null ? '' : String(val);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const csv = [
      headers.join(','),
      ...rows.map((n) =>
        [
          n.ssid,
          n.enabled,
          n.security,
          n.band,
          n.vlan_id ?? '',
          n.hidden,
          n.guest_network,
          n.client_isolation,
          n.band_steering,
          n.fast_roaming,
          n.rate_limit_enabled,
          n.rate_limit_down ?? '',
          n.rate_limit_up ?? '',
        ]
          .map(esc)
          .join(','),
      ),
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `wifi-networks-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [filteredNetworks]);

  // ── Render ──────────────────────────────────────
  const renderContent = () => {
    if (isError) {
      return (
        <div className="space-y-6">
          <PageHeader
            icon={Wifi}
            title={t('WifiNetworksPage.page.title')}
            description={t('WifiNetworksPage.page.descriptionShort')}
          />
          <ErrorState message={t('WifiNetworksPage.page.loadError')} onRetry={() => refetch()} />
        </div>
      );
    }

    if (selectedNetwork) {
      return (
        <WifiDetailPanel
          network={selectedNetwork}
          onClose={() => selectNetwork(undefined)}
          onEdit={() => setEditingNetwork(selectedNetwork)}
          onToggle={() =>
            toggleMutation.mutate({
              id: selectedNetwork.id,
              enabled: !selectedNetwork.enabled,
            })
          }
        />
      );
    }

    return (
      <div className="space-y-6">
        <PageHeader
          icon={Wifi}
          title={t('WifiNetworksPage.page.title')}
          titleBadge={<CapabilityMaturityBadge capabilityId="wifi_radius" />}
          description={t('WifiNetworksPage.page.description')}
          onRefresh={() => refetch()}
          refreshing={isLoading}
          secondaryActions={[{ label: t('WifiNetworksPage.actions.export'), icon: Download, onClick: handleExport }]}
          primaryAction={{
            label: t('WifiNetworksPage.actions.addNetwork'),
            icon: Plus,
            onClick: () => setCreateDialogOpen(true),
          }}
        />

        <StatsGrid
          columns={4}
          isLoading={isLoading}
          stats={[
            {
              title: t('WifiNetworksPage.stats.totalNetworks'),
              value: stats.total,
              icon: Wifi,
              variant: 'default',
              description: t('WifiNetworksPage.stats.configuredSsids'),
            },
            {
              title: t('WifiNetworksPage.stats.active'),
              value: stats.active,
              icon: Power,
              variant: 'success',
              description:
                stats.total > 0
                  ? t('WifiNetworksPage.stats.percentEnabled', {
                      percent: Math.round((stats.active / stats.total) * 100),
                    })
                  : t('WifiNetworksPage.stats.noNetworks'),
            },
            {
              title: t('WifiNetworksPage.stats.guest'),
              value: stats.guest,
              icon: Globe,
              variant: 'info',
              description: t('WifiNetworksPage.stats.guestSsids'),
            },
            {
              title: t('WifiNetworksPage.stats.hidden'),
              value: stats.hidden,
              icon: EyeOff,
              variant: 'warning',
              description: t('WifiNetworksPage.stats.nonBroadcasting'),
            },
          ]}
        />

        <PageToolbar>
          <SearchBar
            value={searchQuery}
            onChange={setSearchQuery}
            placeholder={t('WifiNetworksPage.filters.searchPlaceholder')}
            className="w-full sm:w-auto"
          />
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-full sm:w-[160px]">
              <SelectValue placeholder={t('WifiNetworksPage.filters.allStatuses')} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t('WifiNetworksPage.filters.allStatuses')}</SelectItem>
              <SelectItem value="active">{t('WifiNetworksPage.status.active')}</SelectItem>
              <SelectItem value="disabled">{t('WifiNetworksPage.status.disabled')}</SelectItem>
              <SelectItem value="guest">{t('WifiNetworksPage.filters.guestOnly')}</SelectItem>
            </SelectContent>
          </Select>
          <Select value={bandFilter} onValueChange={setBandFilter}>
            <SelectTrigger className="w-full sm:w-[160px]">
              <SelectValue placeholder={t('WifiNetworksPage.filters.allBands')} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t('WifiNetworksPage.filters.allBands')}</SelectItem>
              <SelectItem value="2.4ghz">2.4 GHz</SelectItem>
              <SelectItem value="5ghz">5 GHz</SelectItem>
              <SelectItem value="both">{t('WifiNetworksPage.filters.dualBand')}</SelectItem>
            </SelectContent>
          </Select>
          {hasActiveFilters && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setSearchQuery('');
                setStatusFilter('all');
                setBandFilter('all');
              }}
            >
              {t('WifiNetworksPage.filters.clearFilters')}
            </Button>
          )}
        </PageToolbar>

        <DataTable
          data={filteredNetworks}
          columns={columns}
          isLoading={isLoading}
          selectable
          onSelectionChange={setSelectedRows}
          searchable={false}
          itemName={t('WifiNetworksPage.itemNamePlural')}
          getRowId={(row) => row.id}
        />

        <BulkActionsBar
          selectedCount={selectedRows.length}
          itemName={t('WifiNetworksPage.itemName')}
          onClear={() => setSelectedRows([])}
          actions={[
            {
              label: t('WifiNetworksPage.actions.enable'),
              icon: Power,
              onClick: () => {
                selectedRows.forEach((n) =>
                  toggleMutation.mutate({ id: n.id, enabled: true }),
                );
                setSelectedRows([]);
              },
            },
            {
              label: t('WifiNetworksPage.actions.disable'),
              icon: PowerOff,
              onClick: () => {
                selectedRows.forEach((n) =>
                  toggleMutation.mutate({ id: n.id, enabled: false }),
                );
                setSelectedRows([]);
              },
            },
            {
              label: t('WifiNetworksPage.actions.delete'),
              icon: Trash2,
              variant: 'destructive',
              onClick: () => {
                if (selectedRows.length === 0) return;
                if (!window.confirm(t('WifiNetworksPage.toast.bulkDeleteTitle'))) return;
                selectedRows.forEach((n) => deleteMutation.mutate(n.id));
                setSelectedRows([]);
              },
            },
          ]}
        />
      </div>
    );
  };

  return (
    <>
      {renderContent()}

      {/* Create Dialog · always rendered */}
      <WifiFormDialog
        open={createDialogOpen}
        onOpenChange={setCreateDialogOpen}
        onSubmit={(d) => createMutation.mutate(d as WifiNetworkCreate)}
        isLoading={createMutation.isPending}
      />

      {/* Edit Dialog · always rendered (works from detail panel too) */}
      {editingNetwork && (
        <WifiFormDialog
          key={editingNetwork.id}
          open={!!editingNetwork}
          onOpenChange={(open) => !open && setEditingNetwork(undefined)}
          network={editingNetwork}
          onSubmit={(d) =>
            editingNetwork &&
            updateMutation.mutate({
              id: editingNetwork.id,
              data: d as WifiNetworkUpdate,
            })
          }
          isLoading={updateMutation.isPending}
        />
      )}

      {/* Delete Confirmation · always rendered */}
      <AlertDialog
        open={!!deletingNetwork}
        onOpenChange={(open) => !open && setDeletingNetwork(undefined)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('WifiNetworksPage.deleteDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('WifiNetworksPage.deleteDialog.description', {
                ssid: deletingNetwork?.ssid ?? '',
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('WifiNetworksPage.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() =>
                deletingNetwork && deleteMutation.mutate(deletingNetwork.id)
              }
              className="bg-destructive hover:bg-destructive/90"
            >
              {deleteMutation.isPending
                ? t('WifiNetworksPage.actions.deleting')
                : t('WifiNetworksPage.actions.deleteNetwork')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
