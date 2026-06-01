// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Add Gateway Page
 *
 * Multi-step wizard for adding a new firewall gateway integration.
 * Steps: 1) Select vendor  2) Enter credentials  3) Test connection  4) Configure & save
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Server,
  ArrowLeft,
  ArrowRight,
  Check,
  Loader2,
  Shield,
  Network,
  CheckCircle,
  XCircle,
  Eye,
  EyeOff,
  RefreshCw,
  Circle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { PageHeader } from '@/components/layout';
import { useToast } from '@/hooks/use-toast';
import {
  gatewayApi,
  type GatewayConnectionCreate,
  type GatewayTestRequest,
  type GatewayTestResponse,
} from '@/lib/api';
import { cn } from '@/lib/utils';
import { useSiteStore } from '@/stores/siteStore';

// ─── Types ─────────────────────────────────────────────────────────────

type Vendor = 'opnsense' | 'pfsense' | 'mikrotik' | 'openwrt';
type Step = 'vendor' | 'credentials' | 'test' | 'configure';

interface VendorInfo {
  id: Vendor;
  name: string;
  /** Translation key suffix for the vendor description (translated at the use site) */
  descriptionKey: string;
  /** Tailwind text color class for the vendor's brand dot (e.g. 'text-blue-500') */
  color: string;
  authType: 'api_key' | 'basic';
  defaultPort: number;
  /** Translation key suffix for the vendor docs hint (translated at the use site) */
  docsKey: string;
}

const vendors: VendorInfo[] = [
  {
    id: 'opnsense',
    name: 'OPNsense',
    descriptionKey: 'vendors.opnsense.description',
    color: 'text-orange-500',
    authType: 'api_key',
    defaultPort: 443,
    docsKey: 'vendors.opnsense.docs',
  },
  {
    id: 'pfsense',
    name: 'pfSense',
    descriptionKey: 'vendors.pfsense.description',
    color: 'text-blue-500',
    authType: 'api_key',
    defaultPort: 443,
    docsKey: 'vendors.pfsense.docs',
  },
  {
    id: 'mikrotik',
    name: 'MikroTik',
    descriptionKey: 'vendors.mikrotik.description',
    color: 'text-sky-500',
    authType: 'basic',
    defaultPort: 443,
    docsKey: 'vendors.mikrotik.docs',
  },
  {
    id: 'openwrt',
    name: 'OpenWRT',
    descriptionKey: 'vendors.openwrt.description',
    color: 'text-green-500',
    authType: 'basic',
    defaultPort: 443,
    docsKey: 'vendors.openwrt.docs',
  },
];

const STEPS: Step[] = ['vendor', 'credentials', 'test', 'configure'];

// ─── Component ─────────────────────────────────────────────────────────

export default function AddGatewayPage() {
  const { t } = useTranslation('firewall');
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // Wizard state
  const [step, setStep] = useState<Step>('vendor');
  const [selectedVendor, setSelectedVendor] = useState<VendorInfo | null>(null);

  // Form state
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [host, setHost] = useState('');
  const [port, setPort] = useState<number>(443);
  const [verifySsl, setVerifySsl] = useState(false);
  const [apiKey, setApiKey] = useState('');
  const [apiSecret, setApiSecret] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showSecret, setShowSecret] = useState(false);
  const [syncEnabled, setSyncEnabled] = useState(true);
  const [syncInterval, setSyncInterval] = useState(300);

  // Test result
  const [testResult, setTestResult] = useState<GatewayTestResponse | null>(null);

  // ─── Mutations ──────────────────────────────────────────────────────

  const testMutation = useMutation({
    mutationFn: (data: GatewayTestRequest) => gatewayApi.testConnection(data),
    onSuccess: (res) => {
      setTestResult(res.data);
      if (res.data.success) {
        toast({ title: t('AddGatewayPage.toast.connectionSuccess.title'), description: t('AddGatewayPage.toast.connectionSuccess.description', { host: res.data.hostname || host }) });
      }
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      setTestResult({ success: false, message: err?.response?.data?.detail || t('AddGatewayPage.test.failedFallback') });
    },
  });

  const createMutation = useMutation({
    mutationFn: (data: GatewayConnectionCreate) => gatewayApi.create(data),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['gateways'] });
      toast({ title: t('AddGatewayPage.toast.gatewayAdded.title'), description: t('AddGatewayPage.toast.gatewayAdded.description', { name }) });
      navigate(`/firewall/gateways/${res.data.id}`);
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      toast({ title: t('AddGatewayPage.toast.error.title'), description: err?.response?.data?.detail || t('AddGatewayPage.toast.error.fallback'), variant: 'destructive' });
    },
  });

  // ─── Helpers ────────────────────────────────────────────────────────

  const stepIndex = STEPS.indexOf(step);

  function goNext() {
    if (stepIndex < STEPS.length - 1) setStep(STEPS[stepIndex + 1]);
  }
  function goBack() {
    if (stepIndex > 0) {
      setTestResult(null);
      setStep(STEPS[stepIndex - 1]);
    }
  }

  function handleVendorSelect(vendor: VendorInfo) {
    setSelectedVendor(vendor);
    setPort(vendor.defaultPort);
    setStep('credentials');
  }

  function handleTest() {
    if (!selectedVendor) return;
    setTestResult(null);
    const data: GatewayTestRequest = {
      vendor: selectedVendor.id,
      host,
      port,
      verify_ssl: verifySsl,
    };
    if (selectedVendor.authType === 'api_key') {
      data.api_key = apiKey;
      data.api_secret = apiSecret;
    } else {
      data.username = username;
      data.password = password;
    }
    testMutation.mutate(data);
  }

  function handleCreate() {
    if (!selectedVendor) return;
    const data: GatewayConnectionCreate = {
      name: name || `${selectedVendor.name} - ${host}`,
      description,
      vendor: selectedVendor.id,
      host,
      port,
      verify_ssl: verifySsl,
      sync_enabled: syncEnabled,
      sync_interval_seconds: syncInterval,
      site_id: selectedSiteId || undefined,
    };
    if (selectedVendor.authType === 'api_key') {
      data.api_key = apiKey;
      data.api_secret = apiSecret;
    } else {
      data.username = username;
      data.password = password;
    }
    createMutation.mutate(data);
  }

  // ─── Validation ──────────────────────────────────────────────────────
  const hostValid = /^[a-zA-Z0-9._-]+$/.test(host);
  const portValid = port >= 1 && port <= 65535;
  const credsValid = selectedVendor?.authType === 'api_key'
    ? Boolean(apiKey?.trim() && apiSecret?.trim())
    : Boolean(username?.trim() && password);
  const credentialsValid = host && hostValid && portValid && credsValid;

  function getHostError() {
    if (!host) return '';
    if (!hostValid) return t('AddGatewayPage.credentials.hostError');
    return '';
  }
  function getPortError() {
    if (port >= 1 && port <= 65535) return '';
    return t('AddGatewayPage.credentials.portError');
  }

  // ─── Step indicators ────────────────────────────────────────────────

  function StepIndicator() {
    const labels = [
      t('AddGatewayPage.steps.platform'),
      t('AddGatewayPage.steps.credentials'),
      t('AddGatewayPage.steps.test'),
      t('AddGatewayPage.steps.configure'),
    ];
    return (
      <div className="flex items-center justify-center gap-1 mb-8">
        {labels.map((label, i) => (
          <div key={label} className="flex items-center">
            <div className={cn(
              'flex items-center justify-center w-8 h-8 rounded-full text-sm font-medium transition-colors',
              i < stepIndex ? 'bg-primary text-primary-foreground' :
              i === stepIndex ? 'bg-primary text-primary-foreground ring-2 ring-primary/30' :
              'bg-muted text-muted-foreground',
            )}>
              {i < stepIndex ? <Check className="h-4 w-4" /> : i + 1}
            </div>
            <span className={cn(
              'ml-2 text-sm hidden sm:inline',
              i === stepIndex ? 'font-medium text-foreground' : 'text-muted-foreground',
            )}>{label}</span>
            {i < labels.length - 1 && (
              <div className={cn(
                'w-8 sm:w-12 h-px mx-2',
                i < stepIndex ? 'bg-primary' : 'bg-border',
              )} />
            )}
          </div>
        ))}
      </div>
    );
  }

  // ─── Render ─────────────────────────────────────────────────────────

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      <PageHeader
        icon={Server}
        title={t('AddGatewayPage.header.title')}
        subtitle={t('AddGatewayPage.header.subtitle')}
        actions={
          <Button variant="outline" onClick={() => navigate('/firewall/gateways')}>
            <ArrowLeft className="h-4 w-4 mr-2" /> {t('AddGatewayPage.header.backToGateways')}
          </Button>
        }
      />

      <StepIndicator />

      {/* Step 1: Vendor Selection */}
      {step === 'vendor' && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {vendors.map((v) => (
            <Card
              key={v.id}
              className={cn(
                'cursor-pointer transition-all hover:border-primary/50 hover:shadow-md',
                selectedVendor?.id === v.id && 'border-primary ring-2 ring-primary/20',
              )}
              onClick={() => handleVendorSelect(v)}
            >
              <CardContent noOffset className="p-6 text-center space-y-3">
                <div className="flex justify-center">
                  <Circle className={cn('h-9 w-9 fill-current', v.color)} aria-hidden="true" />
                </div>
                <CardTitle className="text-lg">{v.name}</CardTitle>
                <p className="text-sm text-muted-foreground">{t(`AddGatewayPage.${v.descriptionKey}`)}</p>
                <Badge variant="outline" className="text-xs">
                  {v.authType === 'api_key' ? t('AddGatewayPage.vendors.auth.apiKey') : t('AddGatewayPage.vendors.auth.basic')}
                </Badge>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Step 2: Credentials */}
      {step === 'credentials' && selectedVendor && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Circle className={cn('h-4 w-4 fill-current', selectedVendor.color)} aria-hidden="true" />
              {t('AddGatewayPage.credentials.connectionTitle', { vendor: selectedVendor.name })}
            </CardTitle>
            <CardDescription>{t(`AddGatewayPage.${selectedVendor.docsKey}`)}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="host">{t('AddGatewayPage.credentials.hostLabel')}</Label>
                <Input
                  id="host"
                  placeholder={t('AddGatewayPage.credentials.hostPlaceholder')}
                  value={host}
                  onChange={(e) => setHost(e.target.value.trim())}
                  className={cn(host && !hostValid && 'border-red-500')}
                />
                {getHostError() && <p className="text-xs text-red-500">{getHostError()}</p>}
              </div>
              <div className="space-y-2">
                <Label htmlFor="port">{t('AddGatewayPage.credentials.portLabel')}</Label>
                <Input
                  id="port"
                  type="number"
                  min={1}
                  max={65535}
                  value={port}
                  onChange={(e) => setPort(parseInt(e.target.value) || 443)}
                  className={cn(!portValid && 'border-red-500')}
                />
                {getPortError() && <p className="text-xs text-red-500">{getPortError()}</p>}
              </div>
            </div>

            {selectedVendor.authType === 'api_key' ? (
              <>
                <div className="space-y-2">
                  <Label htmlFor="apiKey">{t('AddGatewayPage.credentials.apiKeyLabel')}</Label>
                  <Input
                    id="apiKey"
                    placeholder={t('AddGatewayPage.credentials.apiKeyPlaceholder')}
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    className="font-mono text-sm"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="apiSecret">{t('AddGatewayPage.credentials.apiSecretLabel')}</Label>
                  <div className="relative">
                    <Input
                      id="apiSecret"
                      type={showSecret ? 'text' : 'password'}
                      placeholder={t('AddGatewayPage.credentials.apiSecretPlaceholder')}
                      value={apiSecret}
                      onChange={(e) => setApiSecret(e.target.value)}
                      className="font-mono text-sm pr-10"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="absolute right-0 top-0 h-full px-3"
                      onClick={() => setShowSecret(!showSecret)}
                    >
                      {showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </Button>
                  </div>
                </div>
              </>
            ) : (
              <>
                <div className="space-y-2">
                  <Label htmlFor="username">{t('AddGatewayPage.credentials.usernameLabel')}</Label>
                  <Input
                    id="username"
                    placeholder="admin"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password">{t('AddGatewayPage.credentials.passwordLabel')}</Label>
                  <div className="relative">
                    <Input
                      id="password"
                      type={showSecret ? 'text' : 'password'}
                      placeholder={t('AddGatewayPage.credentials.passwordPlaceholder')}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="pr-10"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="absolute right-0 top-0 h-full px-3"
                      onClick={() => setShowSecret(!showSecret)}
                    >
                      {showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </Button>
                  </div>
                </div>
              </>
            )}

            <div className="flex items-center gap-2">
              <Switch checked={verifySsl} onCheckedChange={setVerifySsl} id="verify-ssl" />
              <Label htmlFor="verify-ssl" className="text-sm">{t('AddGatewayPage.credentials.verifySsl')}</Label>
            </div>
          </CardContent>
          <CardFooter className="flex justify-between">
            <Button variant="outline" onClick={goBack}>
              <ArrowLeft className="h-4 w-4 mr-2" /> {t('AddGatewayPage.actions.back')}
            </Button>
            <Button onClick={goNext} disabled={!credentialsValid}>
              {t('AddGatewayPage.actions.next')} <ArrowRight className="h-4 w-4 ml-2" />
            </Button>
          </CardFooter>
        </Card>
      )}

      {/* Step 3: Test Connection */}
      {step === 'test' && selectedVendor && (
        <Card>
          <CardHeader>
            <CardTitle>{t('AddGatewayPage.test.title')}</CardTitle>
            <CardDescription>
              {t('AddGatewayPage.test.description', { vendor: selectedVendor.name, host, port })}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {!testResult && !testMutation.isPending && (
              <div className="text-center py-8 space-y-4">
                <Network className="h-16 w-16 mx-auto text-muted-foreground" />
                <p className="text-muted-foreground">{t('AddGatewayPage.test.prompt')}</p>
                <Button size="lg" onClick={handleTest} disabled={testMutation.isPending}>
                  {testMutation.isPending ? <Loader2 className="h-5 w-5 mr-2 animate-spin" /> : <Shield className="h-5 w-5 mr-2" />}
                  {testMutation.isPending ? t('AddGatewayPage.test.testing') : t('AddGatewayPage.test.testButton')}
                </Button>
              </div>
            )}

            {testMutation.isPending && (
              <div className="text-center py-8 space-y-4">
                <Loader2 className="h-12 w-12 mx-auto animate-spin text-primary" />
                <p className="text-muted-foreground">{t('AddGatewayPage.test.connecting', { host })}</p>
              </div>
            )}

            {testResult && (
              <div className={cn(
                'rounded-lg border p-6 space-y-4',
                testResult.success ? 'border-green-500/30 bg-green-50 dark:bg-green-950/20' : 'border-red-500/30 bg-red-50 dark:bg-red-950/20',
              )}>
                <div className="flex items-center gap-3">
                  {testResult.success ? (
                    <CheckCircle className="h-8 w-8 text-green-600" />
                  ) : (
                    <XCircle className="h-8 w-8 text-red-600" />
                  )}
                  <div>
                    <h3 className="font-semibold text-lg">
                      {testResult.success ? t('AddGatewayPage.test.resultSuccess') : t('AddGatewayPage.test.resultFailed')}
                    </h3>
                    <p className="text-sm text-muted-foreground">{testResult.message}</p>
                  </div>
                </div>

                {testResult.success && (
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-2">
                    {testResult.hostname && (
                      <div>
                        <p className="text-xs text-muted-foreground">{t('AddGatewayPage.test.details.hostname')}</p>
                        <p className="text-sm font-medium">{testResult.hostname}</p>
                      </div>
                    )}
                    {testResult.version && (
                      <div>
                        <p className="text-xs text-muted-foreground">{t('AddGatewayPage.test.details.version')}</p>
                        <p className="text-sm font-medium">{testResult.version}</p>
                      </div>
                    )}
                    {testResult.model && (
                      <div>
                        <p className="text-xs text-muted-foreground">{t('AddGatewayPage.test.details.model')}</p>
                        <p className="text-sm font-medium">{testResult.model}</p>
                      </div>
                    )}
                    {testResult.latency_ms !== undefined && (
                      <div>
                        <p className="text-xs text-muted-foreground">{t('AddGatewayPage.test.details.latency')}</p>
                        <p className="text-sm font-medium">{t('AddGatewayPage.test.details.latencyValue', { ms: testResult.latency_ms })}</p>
                      </div>
                    )}
                  </div>
                )}

                {testResult.capabilities && testResult.capabilities.length > 0 && (
                  <div className="pt-2">
                    <p className="text-xs text-muted-foreground mb-2">{t('AddGatewayPage.test.detectedCapabilities')}</p>
                    <div className="flex flex-wrap gap-1">
                      {testResult.capabilities.map((cap) => (
                        <Badge key={cap} variant="secondary" className="text-xs">{cap}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex justify-end gap-2 pt-2">
                  <Button variant="outline" size="sm" onClick={handleTest} disabled={testMutation.isPending}>
                    {testMutation.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-1" />}
                    {testMutation.isPending ? t('AddGatewayPage.test.testing') : t('AddGatewayPage.test.retest')}
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
          <CardFooter className="flex justify-between">
            <Button variant="outline" onClick={goBack}>
              <ArrowLeft className="h-4 w-4 mr-2" /> {t('AddGatewayPage.actions.back')}
            </Button>
            <Button onClick={goNext} disabled={!testResult?.success}>
              {t('AddGatewayPage.actions.next')} <ArrowRight className="h-4 w-4 ml-2" />
            </Button>
          </CardFooter>
        </Card>
      )}

      {/* Step 4: Configure & Save */}
      {step === 'configure' && selectedVendor && (
        <Card>
          <CardHeader>
            <CardTitle>{t('AddGatewayPage.configure.title')}</CardTitle>
            <CardDescription>
              {t('AddGatewayPage.configure.description', { vendor: selectedVendor.name })}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">{t('AddGatewayPage.configure.nameLabel')}</Label>
              <Input
                id="name"
                placeholder={`${selectedVendor.name} - ${testResult?.hostname || host}`}
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                {t('AddGatewayPage.configure.nameHelper')}
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="description">{t('AddGatewayPage.configure.descriptionLabel')}</Label>
              <Textarea
                id="description"
                placeholder={t('AddGatewayPage.configure.descriptionPlaceholder')}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={2}
              />
            </div>

            <div className="border rounded-lg p-4 space-y-4">
              <h4 className="font-medium text-sm">{t('AddGatewayPage.configure.sync.heading')}</h4>
              <div className="flex items-center justify-between">
                <div>
                  <Label htmlFor="sync-enabled">{t('AddGatewayPage.configure.sync.enableLabel')}</Label>
                  <p className="text-xs text-muted-foreground">{t('AddGatewayPage.configure.sync.enableHelper')}</p>
                </div>
                <Switch checked={syncEnabled} onCheckedChange={setSyncEnabled} id="sync-enabled" />
              </div>
              {syncEnabled && (
                <div className="space-y-2">
                  <Label htmlFor="sync-interval">{t('AddGatewayPage.configure.sync.intervalLabel')}</Label>
                  <Input
                    id="sync-interval"
                    type="number"
                    min={60}
                    max={86400}
                    value={syncInterval}
                    onChange={(e) => setSyncInterval(parseInt(e.target.value) || 300)}
                  />
                  <p className="text-xs text-muted-foreground">
                    {t('AddGatewayPage.configure.sync.intervalHelper')}
                  </p>
                </div>
              )}
            </div>

            {/* Summary */}
            <div className="border rounded-lg p-4 bg-muted/50 space-y-2">
              <h4 className="font-medium text-sm">{t('AddGatewayPage.configure.summary.heading')}</h4>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <span className="text-muted-foreground">{t('AddGatewayPage.configure.summary.platform')}</span>
                <span>{selectedVendor.name}</span>
                <span className="text-muted-foreground">{t('AddGatewayPage.configure.summary.host')}</span>
                <span>{host}:{port}</span>
                {testResult?.hostname && (
                  <>
                    <span className="text-muted-foreground">{t('AddGatewayPage.configure.summary.detectedHostname')}</span>
                    <span>{testResult.hostname}</span>
                  </>
                )}
                {testResult?.version && (
                  <>
                    <span className="text-muted-foreground">{t('AddGatewayPage.configure.summary.version')}</span>
                    <span>{testResult.version}</span>
                  </>
                )}
                <span className="text-muted-foreground">{t('AddGatewayPage.configure.summary.autoSync')}</span>
                <span>{syncEnabled ? t('AddGatewayPage.configure.summary.everyN', { n: syncInterval }) : t('AddGatewayPage.configure.summary.disabled')}</span>
              </div>
            </div>
          </CardContent>
          <CardFooter className="flex justify-between">
            <Button variant="outline" onClick={goBack}>
              <ArrowLeft className="h-4 w-4 mr-2" /> {t('AddGatewayPage.actions.back')}
            </Button>
            <Button onClick={handleCreate} disabled={createMutation.isPending}>
              {createMutation.isPending ? (
                <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> {t('AddGatewayPage.actions.saving')}</>
              ) : (
                <><Check className="h-4 w-4 mr-2" /> {t('AddGatewayPage.actions.addGateway')}</>
              )}
            </Button>
          </CardFooter>
        </Card>
      )}
    </div>
  );
}
