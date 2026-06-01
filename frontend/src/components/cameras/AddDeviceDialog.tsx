// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Add Camera / NVR Dialog (Enhanced)
 *
 * Two-tab workflow:
 *   1. **Discover NVR** · multi-step wizard:
 *       Step 1  → Enter NVR IP + credentials, test connection.
 *       Step 2  → See discovered channels with search, filter, select all/none.
 *       Step 3  → Import result summary.
 *   2. **Manual Add** · enter IP, port, credentials for a standalone camera.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Camera,
  CheckCircle,
  ChevronRight,
  HardDrive,
  Loader2,
  Monitor,
  Plus,
  Search,
  ServerCog,
  Wifi,
  WifiOff,
  XCircle,
  AlertCircle,
  ArrowLeft,
  Eye,
  EyeOff,
  MapPin,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { MaturityBadge } from '@/components/ui/maturity-badge';
import { Progress } from '@/components/ui/progress';
import { useAdapterMaturity } from '@/hooks/useAdapterMaturity';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { cn } from '@/lib/utils';
import { useAuthStore } from '@/stores/authStore';
import {
  camerasApi,
  nvrApi,
  sitesApi,
  cameraDiscoveryApi,
  type NVRConnectionTestRequest,
  type NVRConnectionTestResponse,
  type NVRDiscoveryResponse,
  type DiscoveredChannel,
  type NVRImportResponse,
  type StandaloneCameraImportResponse,
} from '@/lib/api';

// ─── Host / IP validation ────────────────────────────────────────────────────
// Accept an IPv4 address or a DNS hostname (RFC-1123 labels). Used to gate the
// test/discover buttons and to refine the manual-add ip_address field.
const HOST_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)$/;

const isValidHost = (v: string): boolean => HOST_RE.test(v.trim());

// ─── Site Select with Quick-Create ──────────────────────────────────────────

function SiteSelectWithCreate({
  value,
  onValueChange,
}: {
  value: string;
  onValueChange: (v: string) => void;
}) {
  const { t } = useTranslation('common');
  const queryClient = useQueryClient();
  const { user } = useAuthStore();
  const [creating, setCreating] = useState(false);
  const [newSiteName, setNewSiteName] = useState('');

  const { data: sitesData, isLoading: sitesLoading } = useQuery({
    queryKey: ['sites'],
    queryFn: async () => {
      const response = await sitesApi.getAll({ per_page: 100 });
      return response.data;
    },
  });
  const sites: { id: string; name: string }[] = sitesData?.items || [];

  const createMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) => sitesApi.create(data),
    onSuccess: (res: { data: { id: string } }) => {
      const newSite = res.data;
      queryClient.invalidateQueries({ queryKey: ['sites'] });
      onValueChange(String(newSite.id));
      setCreating(false);
      setNewSiteName('');
    },
  });

  const handleQuickCreate = () => {
    if (!newSiteName.trim()) return;
    const slug = newSiteName.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    createMutation.mutate({
      name: newSiteName.trim(),
      slug: slug || 'site-1',
      organization_id: user?.organization_id,
    });
  };

  if (creating) {
    return (
      <div className="space-y-2">
        <div className="flex gap-2">
          <Input
            value={newSiteName}
            onChange={(e) => setNewSiteName(e.target.value)}
            placeholder={t('AddDeviceDialog.site.namePlaceholder')}
            autoFocus
            className="flex-1"
            onKeyDown={(e) => {
              if (e.key === 'Enter') { e.preventDefault(); handleQuickCreate(); }
              if (e.key === 'Escape') { setCreating(false); setNewSiteName(''); }
            }}
          />
          <Button
            size="sm"
            onClick={handleQuickCreate}
            disabled={!newSiteName.trim() || createMutation.isPending}
            className="shrink-0"
          >
            {createMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : t('AddDeviceDialog.site.create')}
          </Button>
          <Button size="sm" variant="ghost" onClick={() => { setCreating(false); setNewSiteName(''); }} className="shrink-0 px-2">
            <XCircle className="h-4 w-4" />
          </Button>
        </div>
        {createMutation.isError && (
          <p className="text-xs text-red-500">
            {(createMutation.error as any)?.response?.data?.detail || t('AddDeviceDialog.site.createError')}
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="flex gap-2">
      <Select value={value} onValueChange={onValueChange}>
        <SelectTrigger className="flex-1">
          <SelectValue placeholder={sitesLoading ? t('AddDeviceDialog.site.loading') : sites.length === 0 ? t('AddDeviceDialog.site.noSitesCreate') : t('AddDeviceDialog.site.selectPlaceholder')} />
        </SelectTrigger>
        <SelectContent>
          {Array.isArray(sites) && sites.map((s: { id: string; name: string }) => (
            <SelectItem key={s.id} value={String(s.id)}>{s.name}</SelectItem>
          ))}
          {sites.length === 0 && (
            <div className="px-2 py-3 text-center">
              <MapPin className="h-5 w-5 text-muted-foreground mx-auto mb-1" />
              <p className="text-xs text-muted-foreground">{t('AddDeviceDialog.site.noSitesYet')}</p>
              <p className="text-[10px] text-muted-foreground">{t('AddDeviceDialog.site.usePlusButton')}</p>
            </div>
          )}
        </SelectContent>
      </Select>
      <Button
        type="button"
        size="icon"
        variant="outline"
        onClick={() => setCreating(true)}
        className="shrink-0 h-9 w-9"
        title={t('AddDeviceDialog.site.quickCreateTitle')}
      >
        <Plus className="h-4 w-4" />
      </Button>
    </div>
  );
}

// ─── Interfaces ─────────────────────────────────────────────────────────────

interface AddDeviceDialogProps {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onSuccess?: () => void;
}

interface ManualCameraForm {
  name: string;
  ip_address: string;
  port: number;
  username: string;
  password: string;
  camera_type: string;
  site_id: string;
  vendor: string;
  location: string;
}

interface ConnectionForm {
  host: string;
  port: number;
  username: string;
  password: string;
}

type DiscoverStep = 'connect' | 'channels' | 'camera-confirm' | 'unknown-choice' | 'done';

// ─── Main Dialog ────────────────────────────────────────────────────────────

export function AddDeviceDialog({ open, onOpenChange, onSuccess }: AddDeviceDialogProps) {
  const { t } = useTranslation('common');
  const [tab, setTab] = useState<'manual' | 'discover'>('discover');
  // Increment key on close to reset all child state (credentials, wizard progress)
  const [dialogKey, setDialogKey] = useState(0);

  const handleClose = useCallback(() => {
    onOpenChange(false);
    setTab('discover');
    setDialogKey((k) => k + 1);
  }, [onOpenChange]);

  const handleSuccess = useCallback(() => {
    onSuccess?.();
    handleClose();
  }, [onSuccess, handleClose]);

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose(); else onOpenChange(v); }}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader className="pb-4 border-b">
          <DialogTitle className="flex items-center gap-3 text-xl">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <Camera className="h-5 w-5" />
            </span>
            {t('AddDeviceDialog.title')}
          </DialogTitle>
          <DialogDescription className="pt-1">
            {t('AddDeviceDialog.description')}
          </DialogDescription>
        </DialogHeader>

        <Tabs value={tab} onValueChange={(v) => setTab(v as any)} className="flex-1 overflow-hidden flex flex-col">
          <TabsList className="w-full grid grid-cols-2 mb-8 mt-2">
            <TabsTrigger value="discover" className="gap-2">
              <Search className="h-4 w-4" />
              {t('AddDeviceDialog.tabs.discover')}
            </TabsTrigger>
            <TabsTrigger value="manual" className="gap-2">
              <Camera className="h-4 w-4" />
              {t('AddDeviceDialog.tabs.manual')}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="discover" className="flex-1 overflow-auto mt-0">
            <DiscoverTab key={`discover-${dialogKey}`} onSuccess={handleSuccess} onClose={handleClose} />
          </TabsContent>

          <TabsContent value="manual" className="flex-1 overflow-auto mt-0">
            <ManualTab key={`manual-${dialogKey}`} onSuccess={handleSuccess} onClose={handleClose} />
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}

// ─── Manual Add Tab ─────────────────────────────────────────────────────────

const buildManualSchema = (t: (key: string) => string) =>
  z.object({
    name: z.string().min(1, t('AddDeviceDialog.manual.validation.nameRequired')),
    ip_address: z
      .string()
      .min(1, t('AddDeviceDialog.manual.validation.ipRequired'))
      .refine((v) => isValidHost(v), t('AddDeviceDialog.manual.validation.ipInvalid')),
    port: z.coerce.number().int().min(1).max(65535),
    username: z.string(),
    password: z.string(),
    camera_type: z.string().min(1),
    site_id: z.string().min(1, t('AddDeviceDialog.manual.validation.siteRequired')),
    vendor: z.string(),
    location: z.string(),
  });
type ManualFormValues = z.infer<ReturnType<typeof buildManualSchema>>;

const manualDefaults: ManualFormValues = {
  name: '',
  ip_address: '',
  port: 554,
  username: 'admin',
  password: '',
  camera_type: 'ip_camera',
  site_id: '',
  vendor: '',
  location: '',
};

function ManualTab({ onSuccess, onClose }: { onSuccess: () => void; onClose: () => void }) {
  const { t } = useTranslation('common');
  const manualSchema = useMemo(() => buildManualSchema(t), [t]);
  const form = useForm<ManualFormValues>({
    // Cast: zod's resolver type is invariant on the input shape (port: unknown
    // because of z.coerce). Same pattern used by the FormDialog primitive.
    resolver: zodResolver(manualSchema as never) as never,
    defaultValues: manualDefaults,
    mode: 'onSubmit',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [serverError, setServerError] = useState<string | null>(null);
  const { maturityFor } = useAdapterMaturity();
  // Hikvision has a native adapter; every other vendor connects via the generic
  // ONVIF adapter, so its maturity is ONVIF's.
  const cameraMaturity = (vendor?: string) =>
    maturityFor(vendor === 'hikvision' ? 'hikvision' : 'onvif');

  const cameraCreateMutation = useMutation({
    mutationFn: (data: ManualFormValues) => camerasApi.create(data as ManualCameraForm),
    onSuccess: () => onSuccess(),
  });

  // Cast: zod's resolver `as never` cast loses the values type · re-assert here.
  const handleSubmit = form.handleSubmit(async (values) => {
    setServerError(null);
    try {
      await cameraCreateMutation.mutateAsync(values as ManualFormValues);
    } catch (err) {
      const e = err as { response?: { data?: { detail?: string } }; message?: string };
      setServerError(e?.response?.data?.detail || e.message || t('AddDeviceDialog.manual.createError'));
    }
  });

  return (
    <Form {...form}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <FormField
            control={form.control}
            name="name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AddDeviceDialog.manual.cameraName')} <span className="text-red-500">*</span></FormLabel>
                <FormControl>
                  <Input placeholder={t('AddDeviceDialog.manual.cameraNamePlaceholder')} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="site_id"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AddDeviceDialog.common.site')} <span className="text-red-500">*</span></FormLabel>
                <SiteSelectWithCreate value={field.value} onValueChange={field.onChange} />
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <FormField
            control={form.control}
            name="ip_address"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AddDeviceDialog.manual.ipAddress')} <span className="text-red-500">*</span></FormLabel>
                <FormControl>
                  <Input placeholder="192.168.1.100" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="port"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AddDeviceDialog.common.port')}</FormLabel>
                <FormControl>
                  <Input type="number" min={1} max={65535} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <FormField
            control={form.control}
            name="username"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AddDeviceDialog.common.username')}</FormLabel>
                <FormControl>
                  <Input {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="password"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AddDeviceDialog.common.password')}</FormLabel>
                <FormControl>
                  <div className="relative">
                    <Input
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="off"
                      {...field}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      aria-label={showPassword ? t('AddDeviceDialog.common.hidePassword') : t('AddDeviceDialog.common.showPassword')}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <FormField
            control={form.control}
            name="camera_type"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AddDeviceDialog.manual.cameraType')}</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value="ip_camera">{t('AddDeviceDialog.manual.cameraTypes.ipCamera')}</SelectItem>
                    <SelectItem value="ptz_camera">{t('AddDeviceDialog.manual.cameraTypes.ptzCamera')}</SelectItem>
                    <SelectItem value="doorbell">{t('AddDeviceDialog.manual.cameraTypes.doorbell')}</SelectItem>
                    <SelectItem value="intercom">{t('AddDeviceDialog.manual.cameraTypes.intercom')}</SelectItem>
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="vendor"
            render={({ field }) => (
              <FormItem>
                <div className="flex items-center gap-2">
                  <FormLabel>{t('AddDeviceDialog.manual.vendor')}</FormLabel>
                  {field.value && <MaturityBadge info={cameraMaturity(field.value)} />}
                </div>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger><SelectValue placeholder={t('AddDeviceDialog.manual.vendorPlaceholder')} /></SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value="hikvision">Hikvision · {t('vendorSupport.tiers.native')}</SelectItem>
                    <SelectItem value="dahua">Dahua · {t('vendorSupport.tiers.onvif')}</SelectItem>
                    <SelectItem value="axis">Axis · {t('vendorSupport.tiers.onvif')}</SelectItem>
                    <SelectItem value="reolink">Reolink · {t('vendorSupport.tiers.onvif')}</SelectItem>
                    <SelectItem value="uniview">Uniview · {t('vendorSupport.tiers.onvif')}</SelectItem>
                    <SelectItem value="other">{t('AddDeviceDialog.manual.vendors.other')} · {t('vendorSupport.tiers.onvif')}</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">{t('vendorSupport.addHint')}</p>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="location"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AddDeviceDialog.manual.location')}</FormLabel>
                <FormControl>
                  <Input placeholder={t('AddDeviceDialog.manual.locationPlaceholder')} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {serverError && (
          <div className="flex items-center gap-2 text-red-500 text-sm p-3 bg-red-500/5 rounded-lg border border-red-500/20">
            <AlertCircle className="h-4 w-4 shrink-0" />
            {serverError}
          </div>
        )}

        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>{t('AddDeviceDialog.common.cancel')}</Button>
          <Button type="submit" disabled={cameraCreateMutation.isPending}>
            {cameraCreateMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            {t('AddDeviceDialog.manual.addCamera')}
          </Button>
        </DialogFooter>
      </form>
    </Form>
  );
}

// ─── Discover NVR Tab (3-step wizard) ───────────────────────────────────────

function DiscoverTab({ onSuccess, onClose }: { onSuccess: () => void; onClose: () => void }) {
  const { t } = useTranslation('common');
  const queryClient = useQueryClient();
  const [step, setStep] = useState<DiscoverStep>('connect');
  const [connForm, setConnForm] = useState<ConnectionForm>({
    host: '',
    port: 80,
    username: 'admin',
    password: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [testResult, setTestResult] = useState<NVRConnectionTestResponse | null>(null);
  const [discovery, setDiscovery] = useState<NVRDiscoveryResponse | null>(null);
  const [selectedChannels, setSelectedChannels] = useState<Set<number>>(new Set());
  const [importResult, setImportResult] = useState<NVRImportResponse | null>(null);
  const [cameraImportResult, setCameraImportResult] = useState<StandaloneCameraImportResponse | null>(null);
  const [siteId, setSiteId] = useState('');
  const [nvrName, setNvrName] = useState('');
  const [cameraName, setCameraName] = useState('');
  const [channelSearch, setChannelSearch] = useState('');
  const [channelFilter, setChannelFilter] = useState<'all' | 'online' | 'offline'>('all');

  // Sites are fetched by SiteSelectWithCreate component

  // ── Filtered channels ──────────────────────────────

  const filteredChannels = useMemo(() => {
    if (!discovery) return [];
    return discovery.channels.filter((ch) => {
      if (channelSearch) {
        const q = channelSearch.toLowerCase();
        const nameMatch = ch.name.toLowerCase().includes(q);
        const ipMatch = (ch.source_ip || '').toLowerCase().includes(q);
        const chMatch = String(ch.channel_id).includes(q);
        if (!nameMatch && !ipMatch && !chMatch) return false;
      }
      if (channelFilter === 'online' && !ch.online) return false;
      if (channelFilter === 'offline' && ch.online) return false;
      return true;
    });
  }, [discovery, channelSearch, channelFilter]);

  const enabledChannels = useMemo(() => {
    if (!discovery) return [];
    return discovery.channels.filter((c) => c.enabled);
  }, [discovery]);

  const onlineCount = useMemo(() => {
    if (!discovery) return 0;
    return discovery.channels.filter((c) => c.online).length;
  }, [discovery]);

  const offlineCount = useMemo(() => {
    if (!discovery) return 0;
    return discovery.channels.filter((c) => !c.online).length;
  }, [discovery]);

  // ── Step 1: Test connection ─────────────────────────

  const testMutation = useMutation({
    mutationFn: (data: NVRConnectionTestRequest) => nvrApi.testConnection(data),
    onSuccess: (res) => {
      setTestResult(res.data);
    },
  });

  const discoverMutation = useMutation({
    mutationFn: (data: NVRConnectionTestRequest) => nvrApi.discover(data),
    onSuccess: (res) => {
      const data = res.data;
      setDiscovery(data);

      if (data.device_type === 'camera') {
        // Confirmed standalone camera · skip channel selection
        setCameraName(data.nvr?.name || connForm.host);
        setStep('camera-confirm');
      } else if (data.device_type === 'nvr' || data.channels.length > 0) {
        // NVR (or any device that reported channels) · show channel selection
        setNvrName(data.nvr?.name || connForm.host);
        const enabled = new Set(
          data.channels.filter((ch) => ch.enabled).map((ch) => ch.channel_id)
        );
        setSelectedChannels(enabled);
        setStep('channels');
      } else {
        // Unknown device type with no channels · let the user pick instead of
        // silently importing it as a single camera.
        setCameraName(data.nvr?.name || connForm.host);
        setNvrName(data.nvr?.name || connForm.host);
        setStep('unknown-choice');
      }
    },
  });

  // Local-network ONVIF scan, find devices without knowing their IP, then
  // click a result to pre-fill the host field below.
  const scanMutation = useMutation({
    mutationFn: () => cameraDiscoveryApi.scan(5),
  });

  // Editing any connection field invalidates a prior test/discover result so the
  // stale green "Connected" card (and any error banner) can't mislead the user.
  const updateConn = (patch: Partial<ConnectionForm>) => {
    setConnForm((prev) => ({ ...prev, ...patch }));
    if (testResult) setTestResult(null);
    if (testMutation.isError) testMutation.reset();
    if (discoverMutation.isError) discoverMutation.reset();
  };

  const handleTestConnection = () => {
    setTestResult(null);
    testMutation.mutate(connForm);
  };

  const handleDiscover = () => {
    discoverMutation.reset();
    discoverMutation.mutate(connForm);
  };

  // ── Step 2: Channel selection ───────────────────────

  const toggleChannel = (chId: number) => {
    setSelectedChannels((prev) => {
      const next = new Set(prev);
      if (next.has(chId)) next.delete(chId);
      else next.add(chId);
      return next;
    });
  };

  const selectAll = () => {
    const ids = filteredChannels.filter((c) => c.enabled).map((c) => c.channel_id);
    setSelectedChannels((prev) => {
      const next = new Set(prev);
      ids.forEach((id) => next.add(id));
      return next;
    });
  };

  const deselectAll = () => {
    const ids = new Set(filteredChannels.map((c) => c.channel_id));
    setSelectedChannels((prev) => {
      const next = new Set(prev);
      ids.forEach((id) => next.delete(id));
      return next;
    });
  };

  const selectOnlineOnly = () => {
    if (!discovery) return;
    setSelectedChannels(
      new Set(discovery.channels.filter((c) => c.enabled && c.online).map((c) => c.channel_id))
    );
  };

  const allFilteredSelected = filteredChannels.length > 0 &&
    filteredChannels.filter((c) => c.enabled).every((c) => selectedChannels.has(c.channel_id));

  // ── Step 3: Import ─────────────────────────────────

  const invalidateCameraQueries = () => {
    queryClient.invalidateQueries({ queryKey: ['cameras'] });
    queryClient.invalidateQueries({ queryKey: ['nvrs'] });
    queryClient.invalidateQueries({ queryKey: ['nvr-stats'] });
  };

  const importMutation = useMutation({
    mutationFn: () =>
      nvrApi.import({
        host: connForm.host,
        port: connForm.port,
        username: connForm.username,
        password: connForm.password,
        site_id: siteId,
        name: nvrName || undefined,
        selected_channels: [...selectedChannels],
      }),
    onSuccess: (res) => {
      setImportResult(res.data);
      invalidateCameraQueries();
      setStep('done');
    },
  });

  // ── Standalone camera import ────────────────────────

  const cameraImportMutation = useMutation({
    mutationFn: () =>
      nvrApi.importCamera({
        host: connForm.host,
        port: connForm.port,
        username: connForm.username,
        password: connForm.password,
        site_id: siteId,
        name: cameraName || undefined,
      }),
    onSuccess: (res) => {
      setCameraImportResult(res.data);
      invalidateCameraQueries();
      setStep('done');
    },
  });

  // ── Reset ──────────────────────────────────────────

  const handleReset = () => {
    setStep('connect');
    setTestResult(null);
    setDiscovery(null);
    setSelectedChannels(new Set());
    setImportResult(null);
    setCameraImportResult(null);
    setSiteId('');
    setNvrName('');
    setCameraName('');
    setChannelSearch('');
    setChannelFilter('all');
  };

  // ── Render ─────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Step indicator */}
      <div className="flex items-center gap-3 text-sm text-muted-foreground pt-1 pb-4 border-b">
        <StepIndicator step={1} label={t('AddDeviceDialog.discover.steps.connect')} active={step === 'connect'} done={step !== 'connect'} />
        <ChevronRight className="h-4 w-4 shrink-0" />
        <StepIndicator
          step={2}
          label={
            step === 'camera-confirm'
              ? t('AddDeviceDialog.discover.steps.confirmCamera')
              : step === 'unknown-choice'
                ? t('AddDeviceDialog.discover.steps.chooseType')
                : t('AddDeviceDialog.discover.steps.selectChannels')
          }
          active={step === 'channels' || step === 'camera-confirm' || step === 'unknown-choice'}
          done={step === 'done'}
        />
        <ChevronRight className="h-4 w-4 shrink-0" />
        <StepIndicator step={3} label={t('AddDeviceDialog.discover.steps.done')} active={step === 'done'} done={false} />
      </div>

      {/* ──── Step 1: Connect ──── */}
      {step === 'connect' && (
        <div className="space-y-5">
          {/* Local-network scan, find ONVIF cameras/NVRs without knowing the IP. */}
          <div className="rounded-md border bg-muted/30 p-3 space-y-2">
            <div className="flex items-center justify-between gap-3">
              <p className="text-xs text-muted-foreground">{t('AddDeviceDialog.discover.scan.hint')}</p>
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={scanMutation.isPending}
                onClick={() => scanMutation.mutate()}
              >
                {scanMutation.isPending ? (
                  <><Loader2 className="h-4 w-4 mr-1.5 animate-spin" />{t('AddDeviceDialog.discover.scan.scanning')}</>
                ) : (
                  <><Search className="h-4 w-4 mr-1.5" />{t('AddDeviceDialog.discover.scan.button')}</>
                )}
              </Button>
            </div>
            {scanMutation.data && (
              scanMutation.data.data.devices.length > 0 ? (
                <div className="space-y-1 max-h-40 overflow-auto">
                  {scanMutation.data.data.devices.map((d) => (
                    <button
                      type="button"
                      key={d.ip}
                      onClick={() => updateConn({ host: d.ip })}
                      className="w-full flex items-center justify-between rounded px-2 py-1.5 text-left text-xs hover:bg-muted transition-colors"
                    >
                      <span className="font-mono">{d.ip}</span>
                      <span className="text-muted-foreground truncate ml-2">
                        {[d.vendor, d.model].filter(Boolean).join(' · ') || t('AddDeviceDialog.discover.scan.unknownDevice')}
                      </span>
                    </button>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">{t('AddDeviceDialog.discover.scan.none')}</p>
              )
            )}
            {scanMutation.isError && (
              <p className="text-xs text-destructive">{t('AddDeviceDialog.discover.scan.failed')}</p>
            )}
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-5">
            <div className="sm:col-span-2 space-y-2">
              <Label>{t('AddDeviceDialog.discover.connect.ipAddress')}</Label>
              <Input
                value={connForm.host}
                onChange={(e) => updateConn({ host: e.target.value })}
                placeholder="192.168.1.64"
              />
              {connForm.host.trim() !== '' && !isValidHost(connForm.host) && (
                <p className="text-xs text-amber-500">{t('AddDeviceDialog.discover.connect.invalidHost')}</p>
              )}
            </div>
            <div className="space-y-2">
              <Label>{t('AddDeviceDialog.common.port')}</Label>
              <Input
                type="number"
                value={connForm.port}
                onChange={(e) => updateConn({ port: Number(e.target.value) })}
                min={1}
                max={65535}
              />
            </div>
          </div>

          <form onSubmit={e => e.preventDefault()} className="grid grid-cols-1 sm:grid-cols-2 gap-5">
            <div className="space-y-2">
              <Label>{t('AddDeviceDialog.common.username')}</Label>
              <Input
                value={connForm.username}
                onChange={(e) => updateConn({ username: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label>{t('AddDeviceDialog.common.password')}</Label>
              <div className="relative">
                <Input
                  type={showPassword ? 'text' : 'password'}
                  value={connForm.password}
                  onChange={(e) => updateConn({ password: e.target.value })}
                  autoComplete="off"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? t('AddDeviceDialog.common.hidePassword') : t('AddDeviceDialog.common.showPassword')}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>
          </form>

          {testResult && (
            <Card className={cn(
              'border',
              testResult.success ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-red-500/30 bg-red-500/5',
            )}>
              <CardContent noOffset>
                {testResult.success ? (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 text-emerald-500 font-medium">
                      <CheckCircle className="h-4 w-4" />
                      {t('AddDeviceDialog.discover.connect.success')}
                    </div>
                    <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
                      <Detail label={t('AddDeviceDialog.discover.connect.detail.device')} value={testResult.device_name} />
                      <Detail label={t('AddDeviceDialog.discover.connect.detail.type')} value={testResult.device_type} />
                      <Detail label={t('AddDeviceDialog.discover.connect.detail.model')} value={testResult.model} />
                      <Detail label={t('AddDeviceDialog.discover.connect.detail.firmware')} value={testResult.firmware_version} />
                      <Detail label={t('AddDeviceDialog.discover.connect.detail.serial')} value={testResult.serial_number} />
                      <Detail label="MAC" value={testResult.mac_address} />
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-2 text-red-500">
                    <XCircle className="h-4 w-4" />
                    <span className="font-medium">{t('AddDeviceDialog.discover.connect.failed')}</span>
                    <span className="text-sm">{testResult.error}</span>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {testMutation.isError && (
            <div className="flex items-center gap-2 text-red-500 text-sm p-3 bg-red-500/5 rounded-lg border border-red-500/20">
              <AlertCircle className="h-4 w-4 shrink-0" />
              {(testMutation.error as any)?.response?.data?.detail || t('AddDeviceDialog.discover.connect.testError')}
            </div>
          )}

          {discoverMutation.isError && (
            <div className="flex items-center gap-2 text-red-500 text-sm p-3 bg-red-500/5 rounded-lg border border-red-500/20">
              <AlertCircle className="h-4 w-4 shrink-0" />
              {(discoverMutation.error as any)?.response?.data?.detail || t('AddDeviceDialog.discover.connect.discoverError')}
            </div>
          )}

          <DialogFooter className="gap-2 sm:gap-3 pt-2">
            <Button variant="outline" onClick={onClose}>{t('AddDeviceDialog.common.cancel')}</Button>
            <Button
              variant="outline"
              onClick={handleTestConnection}
              disabled={!isValidHost(connForm.host) || !connForm.username || !connForm.password || testMutation.isPending}
            >
              {testMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              <Wifi className="h-4 w-4 mr-2" />
              {t('AddDeviceDialog.discover.connect.test')}
            </Button>
            <Button
              onClick={handleDiscover}
              disabled={!isValidHost(connForm.host) || !connForm.username || !connForm.password || discoverMutation.isPending}
            >
              {discoverMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              <Search className="h-4 w-4 mr-2" />
              {t('AddDeviceDialog.discover.connect.discoverChannels')}
            </Button>
          </DialogFooter>
        </div>
      )}

      {/* ──── Step 2: Channel Selection ──── */}
      {step === 'channels' && discovery && (
        <div className="space-y-4">
          {/* NVR info card */}
          <Card className="border-blue-500/20 bg-blue-500/5">
            <CardContent noOffset>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-blue-500/10">
                  <ServerCog className="h-5 w-5 text-blue-500" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="font-medium">{discovery.nvr.name || connForm.host}</div>
                  <div className="text-sm text-muted-foreground">
                    {discovery.nvr.model} &middot; {discovery.nvr.firmware} &middot; {t('AddDeviceDialog.discover.channels.channelCount', { count: discovery.channels.length })}
                  </div>
                </div>
                {discovery.storage && discovery.storage.total_gb > 0 && (
                  <div className="text-right text-sm">
                    <div className="flex items-center gap-1 text-muted-foreground">
                      <HardDrive className="h-3.5 w-3.5" />
                      {discovery.storage.used_gb?.toFixed(0)} / {discovery.storage.total_gb?.toFixed(0)} GB
                    </div>
                    <Progress
                      value={discovery.storage.percent_used || 0}
                      className="h-1.5 w-24 mt-1"
                    />
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Site + NVR name */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>{t('AddDeviceDialog.common.site')} <span className="text-red-500">*</span></Label>
              <SiteSelectWithCreate value={siteId} onValueChange={setSiteId} />
            </div>
            <div className="space-y-2">
              <Label>{t('AddDeviceDialog.discover.channels.nvrName')}</Label>
              <Input
                value={nvrName}
                onChange={(e) => setNvrName(e.target.value)}
                placeholder={t('AddDeviceDialog.discover.channels.nvrNamePlaceholder')}
              />
            </div>
          </div>

          <Separator />

          {/* Channel list header with search + filter + selection controls */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Label className="text-sm font-medium">{t('AddDeviceDialog.discover.channels.cameraChannels')}</Label>
                <Badge variant="secondary" className="text-xs">
                  {t('AddDeviceDialog.discover.channels.selectedCount', { selected: selectedChannels.size, total: enabledChannels.length })}
                </Badge>
              </div>
              <div className="flex items-center gap-1">
                <Badge
                  variant={channelFilter === 'online' ? 'default' : 'outline'}
                  className="text-[10px] cursor-pointer"
                  role="button"
                  tabIndex={0}
                  aria-pressed={channelFilter === 'online'}
                  aria-label={t('AddDeviceDialog.discover.channels.filterOnline')}
                  onClick={() => setChannelFilter(channelFilter === 'online' ? 'all' : 'online')}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setChannelFilter(channelFilter === 'online' ? 'all' : 'online'); }
                  }}
                >
                  <Wifi className="h-3 w-3 mr-1" />
                  {t('AddDeviceDialog.discover.channels.onlineCount', { count: onlineCount })}
                </Badge>
                <Badge
                  variant={channelFilter === 'offline' ? 'default' : 'outline'}
                  className="text-[10px] cursor-pointer"
                  role="button"
                  tabIndex={0}
                  aria-pressed={channelFilter === 'offline'}
                  aria-label={t('AddDeviceDialog.discover.channels.filterOffline')}
                  onClick={() => setChannelFilter(channelFilter === 'offline' ? 'all' : 'offline')}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setChannelFilter(channelFilter === 'offline' ? 'all' : 'offline'); }
                  }}
                >
                  <WifiOff className="h-3 w-3 mr-1" />
                  {t('AddDeviceDialog.discover.channels.offlineCount', { count: offlineCount })}
                </Badge>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <Search className="h-3.5 w-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={channelSearch}
                  onChange={(e) => setChannelSearch(e.target.value)}
                  placeholder={t('AddDeviceDialog.discover.channels.searchPlaceholder')}
                  className="pl-8 h-8 text-sm"
                />
              </div>
              <Button variant="outline" size="sm" className="h-8 text-xs" onClick={allFilteredSelected ? deselectAll : selectAll}>
                {allFilteredSelected ? t('AddDeviceDialog.discover.channels.deselectAll') : t('AddDeviceDialog.discover.channels.selectAll')}
              </Button>
              <Button variant="outline" size="sm" className="h-8 text-xs" onClick={selectOnlineOnly}>
                {t('AddDeviceDialog.discover.channels.onlineOnly')}
              </Button>
            </div>

            <div className="border rounded-lg divide-y max-h-[260px] overflow-auto">
              {filteredChannels.map((ch) => (
                <ChannelRow
                  key={ch.channel_id}
                  channel={ch}
                  selected={selectedChannels.has(ch.channel_id)}
                  onToggle={() => toggleChannel(ch.channel_id)}
                />
              ))}
              {filteredChannels.length === 0 && discovery.channels.length > 0 && (
                <div className="p-4 text-center text-muted-foreground text-sm">
                  {t('AddDeviceDialog.discover.channels.noMatch')}
                </div>
              )}
              {discovery.channels.length === 0 && (
                <div className="p-6 text-center text-muted-foreground text-sm">
                  {t('AddDeviceDialog.discover.channels.noneDiscovered')}
                </div>
              )}
            </div>
          </div>

          {importMutation.isError && (
            <div className="flex items-center gap-2 text-red-500 text-sm p-3 bg-red-500/5 rounded-lg border border-red-500/20">
              <AlertCircle className="h-4 w-4 shrink-0" />
              {(importMutation.error as any)?.response?.data?.detail || t('AddDeviceDialog.discover.channels.importError')}
            </div>
          )}

          <DialogFooter className="flex-col items-stretch gap-2 sm:flex-row sm:items-center sm:gap-3 pt-2">
            {!siteId && selectedChannels.size > 0 && (
              <p className="text-xs text-muted-foreground sm:mr-auto">{t('AddDeviceDialog.common.selectSiteHint')}</p>
            )}
            <Button variant="outline" onClick={() => setStep('connect')}>
              <ArrowLeft className="h-4 w-4 mr-2" />
              {t('AddDeviceDialog.common.back')}
            </Button>
            <Button
              onClick={() => importMutation.mutate()}
              disabled={selectedChannels.size === 0 || !siteId || importMutation.isPending}
            >
              {importMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              {selectedChannels.size === 1
                ? t('AddDeviceDialog.discover.channels.importCount_one', { count: selectedChannels.size })
                : t('AddDeviceDialog.discover.channels.importCount_other', { count: selectedChannels.size })}
            </Button>
          </DialogFooter>
        </div>
      )}

      {/* ──── Step 2b: Standalone Camera Confirm ──── */}
      {step === 'camera-confirm' && discovery && (
        <div className="space-y-4">
          {/* Camera info card */}
          <Card className="border-amber-500/20 bg-amber-500/5">
            <CardContent noOffset>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-amber-500/10">
                  <Camera className="h-5 w-5 text-amber-500" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{discovery.nvr.name || connForm.host}</span>
                    <Badge variant="secondary" className="text-xs">{t('AddDeviceDialog.discover.cameraConfirm.standaloneCamera')}</Badge>
                  </div>
                  <div className="text-sm text-muted-foreground">
                    {discovery.nvr.model}{discovery.nvr.firmware ? ` \u00b7 ${discovery.nvr.firmware}` : ''}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3">
            <div className="flex items-start gap-2 text-sm">
              <AlertCircle className="h-4 w-4 text-amber-500 mt-0.5 shrink-0" />
              <span className="text-muted-foreground">
                {t('AddDeviceDialog.discover.cameraConfirm.info')}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>{t('AddDeviceDialog.common.site')} <span className="text-red-500">*</span></Label>
              <SiteSelectWithCreate value={siteId} onValueChange={setSiteId} />
            </div>
            <div className="space-y-2">
              <Label>{t('AddDeviceDialog.discover.cameraConfirm.cameraName')}</Label>
              <Input
                value={cameraName}
                onChange={(e) => setCameraName(e.target.value)}
                placeholder={discovery.nvr.name || t('AddDeviceDialog.discover.cameraConfirm.cameraNamePlaceholder')}
              />
            </div>
          </div>

          {cameraImportMutation.isError && (
            <div className="flex items-center gap-2 text-red-500 text-sm p-3 bg-red-500/5 rounded-lg border border-red-500/20">
              <AlertCircle className="h-4 w-4 shrink-0" />
              {(cameraImportMutation.error as any)?.response?.data?.detail || t('AddDeviceDialog.discover.cameraConfirm.importError')}
            </div>
          )}

          <DialogFooter className="flex-col items-stretch gap-2 sm:flex-row sm:items-center sm:gap-3 pt-2">
            {!siteId && (
              <p className="text-xs text-muted-foreground sm:mr-auto">{t('AddDeviceDialog.common.selectSiteHint')}</p>
            )}
            <Button variant="outline" onClick={() => setStep('connect')}>
              <ArrowLeft className="h-4 w-4 mr-2" />
              {t('AddDeviceDialog.common.back')}
            </Button>
            <Button
              onClick={() => cameraImportMutation.mutate()}
              disabled={!siteId || cameraImportMutation.isPending}
            >
              {cameraImportMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              {t('AddDeviceDialog.discover.cameraConfirm.importCamera')}
            </Button>
          </DialogFooter>
        </div>
      )}

      {/* ──── Step 2c: Unknown device · let the user choose ──── */}
      {step === 'unknown-choice' && discovery && (
        <div className="space-y-4">
          <Card className="border-amber-500/20 bg-amber-500/5">
            <CardContent noOffset>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-amber-500/10">
                  <AlertCircle className="h-5 w-5 text-amber-500" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{discovery.nvr.name || connForm.host}</span>
                    <Badge variant="secondary" className="text-xs">{t('AddDeviceDialog.discover.unknownChoice.unknownType')}</Badge>
                  </div>
                  <div className="text-sm text-muted-foreground">
                    {discovery.nvr.model || t('AddDeviceDialog.discover.unknownChoice.noModel')}{discovery.nvr.firmware ? ` · ${discovery.nvr.firmware}` : ''}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3">
            <div className="flex items-start gap-2 text-sm">
              <AlertCircle className="h-4 w-4 text-amber-500 mt-0.5 shrink-0" />
              <span className="text-muted-foreground">
                {t('AddDeviceDialog.discover.unknownChoice.info')}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setStep('camera-confirm')}
              className="flex flex-col items-center gap-2 rounded-lg border p-4 text-center hover:border-primary/50 hover:bg-muted/40 transition-colors"
            >
              <Camera className="h-6 w-6 text-amber-500" />
              <span className="text-sm font-medium">{t('AddDeviceDialog.discover.unknownChoice.asCamera')}</span>
              <span className="text-xs text-muted-foreground">{t('AddDeviceDialog.discover.unknownChoice.asCameraHint')}</span>
            </button>
            <button
              type="button"
              onClick={() => { setSelectedChannels(new Set()); setStep('channels'); }}
              className="flex flex-col items-center gap-2 rounded-lg border p-4 text-center hover:border-primary/50 hover:bg-muted/40 transition-colors"
            >
              <ServerCog className="h-6 w-6 text-blue-500" />
              <span className="text-sm font-medium">{t('AddDeviceDialog.discover.unknownChoice.asNvr')}</span>
              <span className="text-xs text-muted-foreground">{t('AddDeviceDialog.discover.unknownChoice.asNvrHint')}</span>
            </button>
          </div>

          <DialogFooter className="gap-2 sm:gap-3 pt-2">
            <Button variant="outline" onClick={() => setStep('connect')}>
              <ArrowLeft className="h-4 w-4 mr-2" />
              {t('AddDeviceDialog.common.back')}
            </Button>
          </DialogFooter>
        </div>
      )}

      {/* ──── Step 3: Done ──── */}
      {step === 'done' && !(importResult || cameraImportResult) && (
        <div className="space-y-4">
          <div className="flex flex-col items-center py-6 text-center">
            <AlertCircle className="h-8 w-8 text-amber-500 mb-4" />
            <h3 className="text-lg font-semibold">{t('AddDeviceDialog.discover.done.errorTitle')}</h3>
            <p className="text-muted-foreground text-sm mt-1">
              {t('AddDeviceDialog.discover.done.errorDescription')}
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={handleReset}>{t('AddDeviceDialog.discover.done.tryAgain')}</Button>
            <Button onClick={onClose}>{t('AddDeviceDialog.common.close')}</Button>
          </DialogFooter>
        </div>
      )}
      {step === 'done' && (importResult || cameraImportResult) && (
        <div className="space-y-4">
          <div className="flex flex-col items-center py-6 text-center">
            <div className="p-3 rounded-full bg-emerald-500/10 mb-4">
              <CheckCircle className="h-8 w-8 text-emerald-500" />
            </div>
            <h3 className="text-lg font-semibold">{t('AddDeviceDialog.discover.done.completeTitle')}</h3>
            <p className="text-muted-foreground text-sm mt-1">
              {importResult
                ? <>
                    {(() => {
                      // On an idempotent re-import (synced) cameras_imported is 0,
                      // phrase it as "already imported" so we don't overstate a
                      // fresh import. Otherwise report the count actually imported.
                      if (importResult.synced) {
                        const n = importResult.cameras.length;
                        return n === 1
                          ? t('AddDeviceDialog.discover.done.camerasSynced_one', { count: n })
                          : t('AddDeviceDialog.discover.done.camerasSynced_other', { count: n });
                      }
                      const n = importResult.cameras_imported;
                      return n === 1
                        ? t('AddDeviceDialog.discover.done.camerasImported_one', { count: n })
                        : t('AddDeviceDialog.discover.done.camerasImported_other', { count: n });
                    })()}
                    {importResult.cameras_skipped > 0 && t('AddDeviceDialog.discover.done.camerasSkipped', { count: importResult.cameras_skipped })}
                  </>
                : cameraImportResult
                  ? <>{t('AddDeviceDialog.discover.done.cameraImportedSuccess', { name: cameraImportResult.camera_name })}</>
                  : null
              }
            </p>
          </div>

          <div className="border rounded-lg divide-y max-h-[200px] overflow-auto">
            {importResult ? importResult.cameras.map((cam) => (
              <div key={cam.id} className="flex items-center gap-3 px-4 py-2.5">
                <CheckCircle className="h-4 w-4 text-emerald-500 shrink-0" />
                <span className="text-sm font-medium flex-1">{cam.name}</span>
                {cam.channel_id != null && (
                  <Badge variant="outline" className="text-xs">{t('AddDeviceDialog.discover.done.channelBadge', { id: cam.channel_id })}</Badge>
                )}
              </div>
            )) : cameraImportResult ? (
              <div className="flex items-center gap-3 px-4 py-2.5">
                <CheckCircle className="h-4 w-4 text-emerald-500 shrink-0" />
                <span className="text-sm font-medium flex-1">{cameraImportResult.camera_name}</span>
                <Badge variant="secondary" className="text-xs">{t('AddDeviceDialog.discover.done.standalone')}</Badge>
              </div>
            ) : null}
          </div>

          <DialogFooter className="gap-2 sm:gap-3 pt-2">
            <Button variant="outline" onClick={handleReset}>
              {t('AddDeviceDialog.discover.done.addAnother')}
            </Button>
            <Button onClick={onSuccess}>
              {t('AddDeviceDialog.discover.done.done')}
            </Button>
          </DialogFooter>
        </div>
      )}
    </div>
  );
}

// ─── Sub-components ─────────────────────────────────────────────────────────

function StepIndicator({ step, label, active, done }: { step: number; label: string; active: boolean; done: boolean }) {
  return (
    <div className={cn('flex items-center gap-1.5', active && 'text-foreground font-medium')}>
      <span
        className={cn(
          'flex items-center justify-center h-6 w-6 shrink-0 rounded-full text-xs font-semibold border',
          active && 'bg-primary text-primary-foreground border-primary',
          done && 'bg-emerald-500 text-white border-emerald-500',
          !active && !done && 'border-muted-foreground/40',
        )}
      >
        {done ? <CheckCircle className="h-3 w-3" /> : step}
      </span>
      <span className="hidden sm:inline">{label}</span>
    </div>
  );
}

function ChannelRow({
  channel,
  selected,
  onToggle,
}: {
  channel: DiscoveredChannel;
  selected: boolean;
  onToggle: () => void;
}) {
  const { t } = useTranslation('common');
  return (
    <label
      className={cn(
        'flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-muted/50 transition-colors',
        selected && 'bg-primary/5',
        !channel.enabled && 'opacity-40 pointer-events-none',
      )}
    >
      <Checkbox
        checked={selected}
        onCheckedChange={() => onToggle()}
        disabled={!channel.enabled}
      />
      <div className="p-1.5 rounded bg-muted">
        <Monitor className="h-3.5 w-3.5 text-muted-foreground" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium flex items-center gap-2">
          <span className="truncate">{channel.name}</span>
          <Badge variant="outline" className="text-[10px] font-normal shrink-0">
            {t('AddDeviceDialog.discover.done.channelBadge', { id: channel.channel_id })}
          </Badge>
        </div>
        <div className="text-xs text-muted-foreground">
          {channel.source_ip || t('AddDeviceDialog.channelRow.noSourceIp')}
        </div>
      </div>
      <div className="flex items-center gap-1.5 shrink-0">
        {channel.has_ptz && (
          <Badge variant="secondary" className="text-[10px]">PTZ</Badge>
        )}
        {channel.has_audio && (
          <Badge variant="secondary" className="text-[10px]">{t('AddDeviceDialog.channelRow.audio')}</Badge>
        )}
        {channel.online ? (
          <Wifi className="h-3.5 w-3.5 text-emerald-500" />
        ) : (
          <WifiOff className="h-3.5 w-3.5 text-red-500" />
        )}
      </div>
    </label>
  );
}

function Detail({ label, value }: { label: string; value?: string | null }) {
  if (!value) return null;
  return (
    <div className="flex items-baseline gap-1">
      <span className="text-muted-foreground">{label}:</span>
      <span className="font-medium truncate">{value}</span>
    </div>
  );
}
