// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Add Controller Modal
 *
 * Multi-step wizard for adding a network controller, built on the canonical
 * WizardDialog primitive.
 *
 * Step layout (dynamic via useMemo on controller_type):
 *   - Non-Omada types: 1 step  → "Connection details" only
 *   - Omada types:     2 steps → "Connection details" → "Site mapping"
 *
 * The Omada-only "probe remote sites" call runs as Step 1's `validate` async
 * hook · it executes when the user clicks Next, and either returns an error
 * string (blocks advance) or returns undefined (advances to Step 2).
 *
 * The Test Connection panel is inline in Step 1's content with its own
 * ephemeral state (testResult / testError / isTesting) · independent of the
 * wizard's step navigation.
 *
 * Site mappings live in local state because they have a variable shape (one
 * entry per remote site, populated post-probe).
 */

import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { z } from 'zod';
import {
  Loader2, Server, Eye, EyeOff, XCircle, Cloud, Monitor, MapPin,
  CheckCircle, TestTube, Zap, Info,
} from 'lucide-react';
import { WizardDialog, type WizardStep } from '@/components/ui/wizard-dialog';
import {
  FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage,
} from '@/components/ui/form';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { MaturityBadge } from '@/components/ui/maturity-badge';
import { useAdapterMaturity } from '@/hooks/useAdapterMaturity';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { controllersApi, sitesApi } from '@/lib/api';

interface AddControllerModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface RemoteSite {
  id: string;
  name: string;
}

interface TestResult {
  success: boolean;
  message: string;
  error?: string;
  details?: {
    latency_ms?: number;
    controller_version?: string;
    controller_name?: string;
    mode?: string;
  };
}

// Only controller types backed by a real, shipping adapter are listed. Each is
// badged with its honest maturity (Verified vs Experimental) from the backend
// (app/adapters/maturity.py). Cisco Meraki and Generic SNMP were removed — they
// had no adapter and would fail on sync, so they aren't offered.
const CONTROLLER_TYPES = [
  // SDN / Wireless controllers
  { value: 'omada', label: 'TP-Link Omada', defaultPort: 443, supportsCloud: true },
  { value: 'unifi', label: 'Ubiquiti UniFi', defaultPort: 443, supportsCloud: false },
  // Gateways / Firewalls (backend supports them via gateway-opnsense-*,
  // gateway-pfsense-*, gateway-mikrotik-*, gateway-openwrt-* surface).
  { value: 'opnsense', label: 'OPNsense', defaultPort: 443, supportsCloud: false },
  { value: 'pfsense', label: 'pfSense', defaultPort: 443, supportsCloud: false },
  { value: 'mikrotik', label: 'MikroTik RouterOS', defaultPort: 443, supportsCloud: false },
  { value: 'openwrt', label: 'OpenWrt', defaultPort: 443, supportsCloud: false },
];

const buildCloudRegions = (t: TFunction) => [
  { value: 'use1', label: t('AddControllerModal.cloudRegions.use1', { code: 'use1' }) },
  { value: 'euw1', label: t('AddControllerModal.cloudRegions.euw1', { code: 'euw1' }) },
  { value: 'aps1', label: t('AddControllerModal.cloudRegions.aps1', { code: 'aps1' }) },
];

// Cross-field validation: enforces local-vs-cloud branch requirements and
// site selection (only for non-Omada types · Omada resolves site during the
// site-binding step).
const schema = z
  .object({
    name: z.string().min(1, 'Controller name is required'),
    site_id: z.string(),
    controller_type: z.string().min(1, 'Please select a controller type'),
    host: z.string(),
    port: z.coerce.number().int().min(1).max(65535),
    username: z.string(),
    password: z.string(),
    use_ssl: z.boolean(),
    verify_ssl: z.boolean(),
    sync_enabled: z.boolean(),
    sync_interval_seconds: z.coerce.number().int().positive(),
    connection_mode: z.enum(['local', 'cloud']),
    client_id: z.string(),
    client_secret: z.string(),
    omada_id: z.string(),
    cloud_region: z.string(),
  })
  .superRefine((data, ctx) => {
    const isOmada = data.controller_type === 'omada';
    const isCloudMode = data.connection_mode === 'cloud';

    if (isCloudMode) {
      if (!data.client_id.trim()) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['client_id'], message: 'Client ID is required for cloud mode' });
      }
      if (!data.client_secret.trim()) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['client_secret'], message: 'Client Secret is required for cloud mode' });
      }
      if (!data.omada_id.trim()) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['omada_id'], message: 'Omada Controller ID is required for cloud mode' });
      }
      if (!data.cloud_region) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['cloud_region'], message: 'Cloud region is required for cloud mode' });
      }
    } else {
      if (!data.host.trim()) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['host'], message: 'Host address is required' });
      }
      if (!data.username.trim()) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['username'], message: 'Username is required' });
      }
      if (!data.password) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['password'], message: 'Password is required' });
      }
    }

    if (!isOmada && !data.site_id) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['site_id'], message: 'Please select a site' });
    }
  });

type ControllerFormValues = z.infer<typeof schema>;

const defaultValues: ControllerFormValues = {
  name: '',
  site_id: '',
  controller_type: '',
  host: '',
  port: 443,
  username: '',
  password: '',
  use_ssl: true,
  verify_ssl: true,
  sync_enabled: true,
  sync_interval_seconds: 300,
  connection_mode: 'local',
  client_id: '',
  client_secret: '',
  omada_id: '',
  cloud_region: '',
};

// All step-1 schema fields that the wizard validates before allowing advance.
// (The full schema's superRefine runs again on final submit.)
const STEP1_FIELDS = [
  'name',
  'site_id',
  'controller_type',
  'host',
  'port',
  'username',
  'password',
  'use_ssl',
  'verify_ssl',
  'connection_mode',
  'client_id',
  'client_secret',
  'omada_id',
  'cloud_region',
] as const;

export function AddControllerModal({ open, onOpenChange }: AddControllerModalProps) {
  const { t } = useTranslation('common');
  const queryClient = useQueryClient();
  const [showPassword, setShowPassword] = useState(false);
  // Mirror of form's controller_type so the parent (outside the render-prop)
  // can compute the steps array via useMemo. Set during render of the step
  // content via a tiny sync hook below.
  const [currentType, setCurrentType] = useState('');

  // Test Connection state · ephemeral, lives outside the form values.
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [isTesting, setIsTesting] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);

  // Site mappings live OUTSIDE the form because they're populated dynamically
  // after probe and have a variable shape (one entry per remote site).
  const [remoteSites, setRemoteSites] = useState<RemoteSite[]>([]);
  const [siteMappings, setSiteMappings] = useState<Record<string, string>>({});

  // Fetch sites for dropdown
  const { data: sitesData } = useQuery({
    queryKey: ['sites'],
    queryFn: async () => {
      const response = await sitesApi.getAll();
      return response.data;
    },
    enabled: open,
  });
  const sites = useMemo(() => sitesData?.items ?? [], [sitesData]);

  const createMutation = useMutation({
    mutationFn: async (payload: Record<string, unknown>) => controllersApi.create(payload),
  });

  const handleOpenChange = (next: boolean) => {
    if (!next) {
      // Reset ephemeral state on close. (Form values are reset by WizardDialog.)
      setShowPassword(false);
      setRemoteSites([]);
      setSiteMappings({});
      setTestResult(null);
      setTestError(null);
      setIsTesting(false);
      setCurrentType('');
    }
    onOpenChange(next);
  };

  const isOmadaType = currentType === 'omada';

  // Build steps dynamically · Omada gets 2, everything else gets 1.
  // (Switching type mid-wizard updates the steps array; since the user
  // hasn't advanced past step 1 yet at that point, it's safe.)
  const steps: WizardStep<ControllerFormValues>[] = useMemo(() => {
    const stepOne: WizardStep<ControllerFormValues> = {
      id: 'details',
      label: t('AddControllerModal.steps.connectionDetails'),
      fields: STEP1_FIELDS as unknown as Array<keyof ControllerFormValues>,
      content: (form) => (
        <ConnectionDetailsStep
          form={form}
          showPassword={showPassword}
          setShowPassword={setShowPassword}
          sites={sites}
          isTesting={isTesting}
          testResult={testResult}
          testError={testError}
          setTestResult={setTestResult}
          setTestError={setTestError}
          setIsTesting={setIsTesting}
          setCurrentType={setCurrentType}
        />
      ),
      // For Omada, probe remote sites and stash them so step 2 can render.
      // For other types, no async work needed.
      validate: async (values) => {
        if (values.controller_type !== 'omada') return undefined;
        try {
          const probePayload: Record<string, unknown> = {
            controller_type: values.controller_type,
            host: values.host || 'cloud',
            port: values.port,
            username: values.username,
            password: values.password,
            use_ssl: values.use_ssl,
            verify_ssl: values.verify_ssl,
            connection_mode: values.connection_mode,
            client_id: values.client_id,
            client_secret: values.client_secret,
            omada_id: values.omada_id,
            cloud_region: values.cloud_region,
          };
          const response = await controllersApi.probeRemoteSites(probePayload);
          const data = response.data;
          setRemoteSites(data.remote_sites || []);
          const initialMappings: Record<string, string> = {};
          for (const rs of data.remote_sites || []) {
            initialMappings[rs.id] = '';
          }
          setSiteMappings(initialMappings);
          return undefined;
        } catch (err: unknown) {
          const axiosErr = err as import('axios').AxiosError<{
            detail?: string;
            error?: { message?: string };
          }>;
          const errObj = err as { code?: string; message?: string };
          const detail =
            axiosErr.response?.data?.detail ||
            axiosErr.response?.data?.error?.message;
          if (detail) return detail;
          if (errObj.code === 'ERR_NETWORK' || errObj.message?.includes('Network Error')) {
            return t('AddControllerModal.probe.networkError');
          }
          return t('AddControllerModal.probe.failed', {
            message: errObj.message || t('AddControllerModal.probe.unknownError'),
          });
        }
      },
    };

    if (!isOmadaType) {
      return [stepOne];
    }

    const stepTwo: WizardStep<ControllerFormValues> = {
      id: 'site-binding',
      label: t('AddControllerModal.steps.siteMapping'),
      fields: [],
      content: () => (
        <SiteBindingStep
          remoteSites={remoteSites}
          siteMappings={siteMappings}
          setSiteMappings={setSiteMappings}
          sites={sites}
        />
      ),
    };

    return [stepOne, stepTwo];
  }, [
    t,
    isOmadaType,
    showPassword,
    sites,
    isTesting,
    testResult,
    testError,
    remoteSites,
    siteMappings,
  ]);

  return (
    <WizardDialog<ControllerFormValues>
      open={open}
      onOpenChange={handleOpenChange}
      title={isOmadaType ? t('AddControllerModal.title.omada') : t('AddControllerModal.title.default')}
      description={
        isOmadaType
          ? t('AddControllerModal.description.omada')
          : t('AddControllerModal.description.default')
      }
      schema={schema}
      defaultValues={defaultValues}
      submitLabel={t('AddControllerModal.submitLabel')}
      contentClassName="sm:max-w-[560px] max-h-[85vh] overflow-y-auto"
      steps={steps}
      onSubmit={async (values) => {
        const activeMappings: Record<string, string> = {};
        for (const [omadaId, freesdnId] of Object.entries(siteMappings)) {
          if (freesdnId && freesdnId !== '__skip__') {
            activeMappings[omadaId] = freesdnId;
          }
        }

        const payload: Record<string, unknown> = { ...values };
        if (values.connection_mode === 'cloud' && !values.host) {
          payload.host = 'cloud';
        }
        if (values.controller_type === 'omada') {
          payload.site_mappings = activeMappings;
          // Use the first mapped FreeSdn site as default site_id if not set.
          payload.site_id = values.site_id || Object.values(activeMappings)[0] || '';
        }

        await createMutation.mutateAsync(payload);
        queryClient.invalidateQueries({ queryKey: ['controllers'] });
        handleOpenChange(false);
      }}
    />
  );
}

// ── Step 1: connection details ────────────────────────────────────────────

interface ConnectionDetailsStepProps {
  form: import('react-hook-form').UseFormReturn<ControllerFormValues>;
  showPassword: boolean;
  setShowPassword: (v: boolean) => void;
  sites: Array<{ id: string; name: string }>;
  isTesting: boolean;
  testResult: TestResult | null;
  testError: string | null;
  setTestResult: (r: TestResult | null) => void;
  setTestError: (e: string | null) => void;
  setIsTesting: (b: boolean) => void;
  setCurrentType: (s: string) => void;
}

function ConnectionDetailsStep({
  form,
  showPassword,
  setShowPassword,
  sites,
  isTesting,
  testResult,
  testError,
  setTestResult,
  setTestError,
  setIsTesting,
  setCurrentType,
}: ConnectionDetailsStepProps) {
  const { t } = useTranslation('common');
  const cloudRegions = useMemo(() => buildCloudRegions(t), [t]);
  const controllerType = form.watch('controller_type');
  const connectionMode = form.watch('connection_mode');
  const host = form.watch('host');
  const port = form.watch('port');
  const username = form.watch('username');
  const password = form.watch('password');
  const useSsl = form.watch('use_ssl');
  const verifySsl = form.watch('verify_ssl');
  const clientId = form.watch('client_id');
  const clientSecret = form.watch('client_secret');
  const omadaId = form.watch('omada_id');
  const cloudRegion = form.watch('cloud_region');

  // Sync the type mirror to the parent so it can recompute the steps array.
  // (setState during render with the same value is a no-op in React.)
  if (controllerType !== undefined) {
    setCurrentType(controllerType);
  }

  const { maturityFor } = useAdapterMaturity();
  const selectedType = CONTROLLER_TYPES.find((t) => t.value === controllerType);
  const isCloudMode = connectionMode === 'cloud';
  const showCloudToggle = selectedType?.supportsCloud ?? false;
  const supportsMultiSite = controllerType === 'omada';

  const handleTypeChange = (value: string) => {
    form.setValue('controller_type', value);
    const type = CONTROLLER_TYPES.find((t) => t.value === value);
    if (type) {
      form.setValue('port', type.defaultPort);
    }
    if (type && !type.supportsCloud) {
      form.setValue('connection_mode', 'local');
      form.setValue('client_id', '');
      form.setValue('client_secret', '');
      form.setValue('omada_id', '');
      form.setValue('cloud_region', '');
    }
  };

  const handleConnectionModeChange = (value: 'local' | 'cloud') => {
    form.setValue('connection_mode', value);
    if (value === 'cloud') {
      form.setValue('username', '');
      form.setValue('password', '');
      form.setValue('host', '');
      form.setValue('port', 443);
    } else {
      form.setValue('client_id', '');
      form.setValue('client_secret', '');
      form.setValue('omada_id', '');
      form.setValue('cloud_region', '');
    }
  };

  const handleTestConnection = async () => {
    if (!controllerType) {
      setTestError(t('AddControllerModal.testErrors.selectType'));
      return;
    }
    if (isCloudMode) {
      if (!clientId || !clientSecret || !omadaId || !cloudRegion) {
        setTestError(t('AddControllerModal.testErrors.cloudRequired'));
        return;
      }
    } else if (!host || !username || !password) {
      setTestError(t('AddControllerModal.testErrors.localRequired'));
      return;
    }

    setIsTesting(true);
    setTestResult(null);
    setTestError(null);
    try {
      const payload: Record<string, unknown> = {
        controller_type: controllerType,
        host: host || 'cloud',
        port,
        username,
        password,
        use_ssl: useSsl,
        verify_ssl: verifySsl,
        connection_mode: connectionMode,
        client_id: clientId,
        client_secret: clientSecret,
        omada_id: omadaId,
        cloud_region: cloudRegion,
      };
      const response = await controllersApi.testConnection(payload);
      setTestResult(response.data);
      if (!response.data.success) {
        setTestError(response.data.error || response.data.message || t('AddControllerModal.testErrors.failed'));
      }
    } catch (err: unknown) {
      const axiosErr = err as import('axios').AxiosError<{ detail?: string }>;
      const errObj = err as { message?: string };
      const detail = axiosErr.response?.data?.detail || errObj.message || t('AddControllerModal.testErrors.failed');
      setTestResult({ success: false, message: detail, error: detail });
      setTestError(detail);
    } finally {
      setIsTesting(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 text-sm font-medium pb-1 -mt-2">
        <Server className="h-5 w-5" />
        <span>{t('AddControllerModal.sections.controllerDetails')}</span>
      </div>

      {/* Controller Name */}
      <FormField
        control={form.control}
        name="name"
        render={({ field }) => (
          <FormItem>
            <FormLabel>{t('AddControllerModal.fields.name.label')}</FormLabel>
            <FormControl>
              <Input placeholder={t('AddControllerModal.fields.name.placeholder')} {...field} />
            </FormControl>
            <FormMessage />
          </FormItem>
        )}
      />

      {/* Site Selection (only for non-multi-site types) */}
      {!supportsMultiSite && (
        <FormField
          control={form.control}
          name="site_id"
          render={({ field }) => (
            <FormItem>
              <FormLabel>{t('AddControllerModal.fields.site.label')}</FormLabel>
              <Select value={field.value} onValueChange={field.onChange}>
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder={t('AddControllerModal.fields.site.placeholder')} />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {sites.map((site) => (
                    <SelectItem key={site.id} value={site.id}>
                      {site.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />
      )}

      {/* Controller Type */}
      <FormField
        control={form.control}
        name="controller_type"
        render={({ field }) => (
          <FormItem>
            <FormLabel>{t('AddControllerModal.fields.controllerType.label')}</FormLabel>
            <Select value={field.value} onValueChange={handleTypeChange}>
              <FormControl>
                <SelectTrigger>
                  <SelectValue placeholder={t('AddControllerModal.fields.controllerType.placeholder')} />
                </SelectTrigger>
              </FormControl>
              <SelectContent>
                {CONTROLLER_TYPES.map((type) => (
                  <SelectItem key={type.value} value={type.value}>
                    <span className="flex items-center gap-2">
                      {type.label}
                      <MaturityBadge info={maturityFor(type.value)} />
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FormMessage />
          </FormItem>
        )}
      />

      {/* Connection Mode Toggle */}
      {showCloudToggle && (
        <FormField
          control={form.control}
          name="connection_mode"
          render={({ field }) => (
            <FormItem>
              <FormLabel>{t('AddControllerModal.connectionMode.label')}</FormLabel>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  className={`flex items-center justify-center gap-2 rounded-md border p-3 text-sm transition-colors ${
                    field.value === 'local'
                      ? 'border-primary bg-primary/10 text-primary font-medium'
                      : 'border-border hover:bg-accent'
                  }`}
                  onClick={() => handleConnectionModeChange('local')}
                >
                  <Monitor className="h-4 w-4" />
                  {t('AddControllerModal.connectionMode.local')}
                </button>
                <button
                  type="button"
                  className={`flex items-center justify-center gap-2 rounded-md border p-3 text-sm transition-colors ${
                    field.value === 'cloud'
                      ? 'border-primary bg-primary/10 text-primary font-medium'
                      : 'border-border hover:bg-accent'
                  }`}
                  onClick={() => handleConnectionModeChange('cloud')}
                >
                  <Cloud className="h-4 w-4" />
                  {t('AddControllerModal.connectionMode.cloud')}
                </button>
              </div>
              <FormDescription>
                {field.value === 'cloud'
                  ? t('AddControllerModal.connectionMode.descriptionCloud')
                  : t('AddControllerModal.connectionMode.descriptionLocal')}
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
      )}

      {/* LOCAL MODE FIELDS */}
      {!isCloudMode && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="sm:col-span-2">
              <FormField
                control={form.control}
                name="host"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('AddControllerModal.fields.host.label')}</FormLabel>
                    <FormControl>
                      <Input placeholder={t('AddControllerModal.fields.host.placeholder')} {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>
            <FormField
              control={form.control}
              name="port"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('AddControllerModal.fields.port.label')}</FormLabel>
                  <FormControl>
                    <Input type="number" min={1} max={65535} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          <FormField
            control={form.control}
            name="username"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AddControllerModal.fields.username.label')}</FormLabel>
                <FormControl>
                  <Input placeholder={t('AddControllerModal.fields.username.placeholder')} {...field} />
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
                <FormLabel>{t('AddControllerModal.fields.password.label')}</FormLabel>
                <FormControl>
                  <div className="relative">
                    <Input
                      type={showPassword ? 'text' : 'password'}
                      placeholder="••••••••"
                      {...field}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                      onClick={() => setShowPassword(!showPassword)}
                    >
                      {showPassword
                        ? <EyeOff className="h-4 w-4 text-muted-foreground" />
                        : <Eye className="h-4 w-4 text-muted-foreground" />}
                    </Button>
                  </div>
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </>
      )}

      {/* CLOUD MODE FIELDS */}
      {isCloudMode && (
        <>
          <FormField
            control={form.control}
            name="cloud_region"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AddControllerModal.fields.cloudRegion.label')}</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder={t('AddControllerModal.fields.cloudRegion.placeholder')} />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {cloudRegions.map((region) => (
                      <SelectItem key={region.value} value={region.value}>
                        {region.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="client_id"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AddControllerModal.fields.clientId.label')}</FormLabel>
                <FormControl>
                  <Input
                    placeholder={t('AddControllerModal.fields.clientId.placeholder')}
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="client_secret"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AddControllerModal.fields.clientSecret.label')}</FormLabel>
                <FormControl>
                  <div className="relative">
                    <Input
                      type={showPassword ? 'text' : 'password'}
                      placeholder="••••••••"
                      {...field}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                      onClick={() => setShowPassword(!showPassword)}
                    >
                      {showPassword
                        ? <EyeOff className="h-4 w-4 text-muted-foreground" />
                        : <Eye className="h-4 w-4 text-muted-foreground" />}
                    </Button>
                  </div>
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="omada_id"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AddControllerModal.fields.omadaId.label')}</FormLabel>
                <FormControl>
                  <Input placeholder={t('AddControllerModal.fields.omadaId.placeholder')} {...field} />
                </FormControl>
                <FormDescription>
                  {t('AddControllerModal.fields.omadaId.descriptionPrefix')}{' '}
                  <code className="text-xs">omadacId</code>{' '}
                  {t('AddControllerModal.fields.omadaId.descriptionSuffix')}
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        </>
      )}

      {/* SSL Options */}
      <FormField
        control={form.control}
        name="use_ssl"
        render={({ field }) => (
          <FormItem>
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <FormLabel>{t('AddControllerModal.ssl.useLabel')}</FormLabel>
                <p className="text-xs text-muted-foreground">{t('AddControllerModal.ssl.useHelper')}</p>
              </div>
              <FormControl>
                <Switch
                  checked={field.value}
                  onCheckedChange={(checked) => {
                    field.onChange(checked);
                    // auto-flip port to the
                    // sensible default for the new scheme so the
                    // operator doesn't have to remember 80 ↔ 443.
                    // Only overrides the OPPOSITE default, preserves
                    // a custom port the operator already typed.
                    const currentPort = form.getValues('port');
                    if (checked && currentPort === 80) {
                      form.setValue('port', 443);
                    } else if (!checked && currentPort === 443) {
                      form.setValue('port', 80);
                    }
                  }}
                />
              </FormControl>
            </div>
            <FormMessage />
          </FormItem>
        )}
      />
      <FormField
        control={form.control}
        name="verify_ssl"
        render={({ field }) => (
          <FormItem>
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <FormLabel>{t('AddControllerModal.ssl.verifyLabel')}</FormLabel>
                <p className="text-xs text-muted-foreground">{t('AddControllerModal.ssl.verifyHelper')}</p>
              </div>
              <FormControl>
                <Switch checked={field.value} onCheckedChange={field.onChange} />
              </FormControl>
            </div>
            <FormMessage />
          </FormItem>
        )}
      />

      {/* Test Connection Panel · non-form ephemeral state */}
      <div className="space-y-3 rounded-lg border border-dashed p-3">
        <div className="flex items-center justify-between">
          <div className="space-y-0.5">
            <Label className="text-sm font-medium">{t('AddControllerModal.test.title')}</Label>
            <p className="text-xs text-muted-foreground">{t('AddControllerModal.test.helper')}</p>
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleTestConnection}
            disabled={
              isTesting ||
              !controllerType ||
              (isCloudMode && (!clientId || !clientSecret || !omadaId || !cloudRegion)) ||
              (!isCloudMode && (!host || !username || !password))
            }
          >
            {isTesting ? (
              <><Loader2 className="mr-2 h-4 w-4 animate-spin" />{t('AddControllerModal.test.testing')}</>
            ) : (
              <><TestTube className="mr-2 h-4 w-4" />{t('AddControllerModal.test.button')}</>
            )}
          </Button>
        </div>

        {testResult && (
          <div className={`rounded-md p-3 text-sm space-y-2 ${
            testResult.success
              ? 'bg-emerald-500/10 border border-emerald-500/20'
              : 'bg-destructive/10 border border-destructive/20'
          }`}>
            <div className="flex items-center gap-2 font-medium">
              {testResult.success ? (
                <>
                  <CheckCircle className="h-4 w-4 text-emerald-500" />
                  <span className="text-emerald-700 dark:text-emerald-400">{t('AddControllerModal.test.successTitle')}</span>
                </>
              ) : (
                <>
                  <XCircle className="h-4 w-4 text-destructive" />
                  <span className="text-destructive">{t('AddControllerModal.test.failedTitle')}</span>
                </>
              )}
            </div>

            {testResult.success && testResult.details && (
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-muted-foreground">
                {testResult.details.latency_ms != null && (
                  <>
                    <span className="flex items-center gap-1"><Zap className="h-3 w-3" /> {t('AddControllerModal.test.details.latency')}</span>
                    <span className="font-medium text-foreground">{t('AddControllerModal.test.details.latencyValue', { ms: testResult.details.latency_ms })}</span>
                  </>
                )}
                {testResult.details.controller_version && (
                  <>
                    <span className="flex items-center gap-1"><Info className="h-3 w-3" /> {t('AddControllerModal.test.details.version')}</span>
                    <span className="font-medium text-foreground">{testResult.details.controller_version}</span>
                  </>
                )}
                {testResult.details.mode && (
                  <>
                    <span className="flex items-center gap-1"><Server className="h-3 w-3" /> {t('AddControllerModal.test.details.mode')}</span>
                    <span className="font-medium text-foreground capitalize">{testResult.details.mode}</span>
                  </>
                )}
              </div>
            )}

            {!testResult.success && testResult.error && (
              <p className="text-xs text-destructive/80 whitespace-pre-line">{testResult.error}</p>
            )}
          </div>
        )}

        {testError && !testResult && (
          <div className="flex gap-2 rounded-md bg-destructive/10 p-3 text-sm text-destructive">
            <XCircle className="h-4 w-4 shrink-0 mt-0.5" />
            <div className="whitespace-pre-line">{testError}</div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Step 2: Omada site mapping ────────────────────────────────────────────

interface SiteBindingStepProps {
  remoteSites: RemoteSite[];
  siteMappings: Record<string, string>;
  setSiteMappings: React.Dispatch<React.SetStateAction<Record<string, string>>>;
  sites: Array<{ id: string; name: string }>;
}

function SiteBindingStep({
  remoteSites,
  siteMappings,
  setSiteMappings,
  sites,
}: SiteBindingStepProps) {
  const { t } = useTranslation('common');
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 text-sm font-medium pb-1 -mt-2">
        <MapPin className="h-5 w-5" />
        <span>{t('AddControllerModal.siteBinding.title')}</span>
      </div>

      <p className="text-sm text-muted-foreground">
        {remoteSites.length === 1
          ? t('AddControllerModal.siteBinding.summaryOne')
          : t('AddControllerModal.siteBinding.summaryMany', { count: remoteSites.length })}
      </p>

      <div className="space-y-3">
        {remoteSites.map((rs) => (
          <div key={rs.id} className="rounded-lg border p-3 space-y-2">
            <div className="flex items-center gap-2">
              <MapPin className="h-4 w-4 text-primary" />
              <span className="font-medium text-sm">{rs.name}</span>
              <span className="text-xs text-muted-foreground">({rs.id})</span>
            </div>
            <Select
              value={siteMappings[rs.id] || '__skip__'}
              onValueChange={(value) =>
                setSiteMappings((prev) => ({
                  ...prev,
                  [rs.id]: value === '__skip__' ? '' : value,
                }))
              }
            >
              <SelectTrigger className="h-9">
                <SelectValue placeholder={t('AddControllerModal.siteBinding.selectPlaceholder')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__skip__">
                  <span className="text-muted-foreground">{t('AddControllerModal.siteBinding.skipOption')}</span>
                </SelectItem>
                {sites.map((site) => (
                  <SelectItem key={site.id} value={site.id}>
                    {site.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        ))}
      </div>

      {remoteSites.length === 0 && (
        <div className="text-center py-4 text-muted-foreground text-sm">
          {t('AddControllerModal.siteBinding.empty')}
        </div>
      )}
    </div>
  );
}
