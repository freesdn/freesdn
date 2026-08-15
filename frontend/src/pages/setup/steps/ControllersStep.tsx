// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Setup Wizard: Controllers Step
 * Includes site-binding step for mapping Omada sites to FreeSdn sites.
 */
import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { setupApi, type ControllerType, type ControllerAddRequest, type ControllerTestResult } from '@/lib/setup-api';
import { sitesApi, getApiErrorMessage } from '@/lib/api';
import { useSetupStore } from '@/stores/setupStore';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { 
  Loader2, 
  Network,
  ChevronRight,
  ChevronLeft,
  Plus,
  CheckCircle2,
  XCircle,
  TestTube,
  Cloud,
  Monitor,
  MapPin,
} from 'lucide-react';

interface ControllersStepProps {
  onNext: () => void;
  onPrevious: () => void;
}

interface AddedController {
  name: string;
  host: string;
  adapter_id: string;
  devices_found: number;
}

interface RemoteSite {
  id: string;
  name: string;
}

type FormStep = 'connection' | 'site-binding';

export function ControllersStep({ onNext, onPrevious }: ControllersStepProps) {
  const { t } = useTranslation('setup');
  const { siteId, addController, setAvailableControllerTypes, availableControllerTypes } = useSetupStore();
  const [loading, setLoading] = useState(true);
  const [controllerTypes, setControllerTypes] = useState<ControllerType[]>([]);
  const [addedControllers, setAddedControllers] = useState<AddedController[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [testing, setTesting] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [testResult, setTestResult] = useState<ControllerTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [formStep, setFormStep] = useState<FormStep>('connection');
  const [remoteSites, setRemoteSites] = useState<RemoteSite[]>([]);
  const [probingRemoteSites, setProbingRemoteSites] = useState(false);
  const [freesdnSites, setFreesdnSites] = useState<Array<{ id: string; name: string }>>([]);
  
  const [formData, setFormData] = useState<ControllerAddRequest>({
    adapter_id: '',
    name: '',
    host: '',
    username: '',
    password: '',
    verify_ssl: true,
    site_id: '',
    connection_mode: 'local',
    client_id: '',
    client_secret: '',
    omada_id: '',
    cloud_region: '',
    site_mappings: {},
  });

  useEffect(() => {
    const loadTypes = async () => {
      try {
        const data = await setupApi.getControllerTypes();
        setControllerTypes(data);
        setAvailableControllerTypes(data);
      } catch (_err) {
        setError(t('ControllersStep.errors.loadTypes'));
      } finally {
        setLoading(false);
      }
    };
    
    if (availableControllerTypes.length > 0) {
      setControllerTypes(availableControllerTypes);
      setLoading(false);
    } else {
      loadTypes();
    }
  }, [availableControllerTypes, setAvailableControllerTypes, t]);

  // Load FreeSdn sites for the binding step
  useEffect(() => {
    const loadSites = async () => {
      try {
        const response = await sitesApi.getAll();
        setFreesdnSites(response.data?.items || []);
      } catch {
        // Sites may not exist yet during setup · that's fine
      }
    };
    loadSites();
  }, []);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleChange = (field: keyof ControllerAddRequest, value: any) => {
    setFormData(prev => {
      const updated = { ...prev, [field]: value };
      
      if (field === 'adapter_id') {
        if (value !== 'omada') {
          updated.connection_mode = 'local';
          updated.client_id = '';
          updated.client_secret = '';
          updated.omada_id = '';
          updated.cloud_region = '';
        }
      }
      
      if (field === 'connection_mode') {
        if (value === 'cloud') {
          updated.username = '';
          updated.password = '';
          updated.host = '';
        } else {
          updated.client_id = '';
          updated.client_secret = '';
          updated.omada_id = '';
          updated.cloud_region = '';
        }
      }
      
      return updated;
    });
    setError(null);
    setTestResult(null);
  };

  const isCloudMode = formData.connection_mode === 'cloud';
  const showCloudToggle = formData.adapter_id === 'omada';
  const supportsMultiSite = formData.adapter_id === 'omada';

  const handleTest = async () => {
    if (isCloudMode) {
      if (!formData.adapter_id || !formData.client_id || !formData.client_secret || !formData.omada_id || !formData.cloud_region) {
        setError(t('ControllersStep.errors.requiredCloudFields'));
        return;
      }
    } else {
      if (!formData.adapter_id || !formData.host || !formData.username || !formData.password) {
        setError(t('ControllersStep.errors.requiredFields'));
        return;
      }
    }
    
    setTesting(true);
    setError(null);
    
    try {
      const payload = { ...formData };
      if (payload.connection_mode === 'cloud' && !payload.host) {
        payload.host = 'cloud';
      }
      const result = await setupApi.testController(payload);
      setTestResult(result);
      
      if (!result.success) {
        setError(result.error || t('ControllersStep.errors.connectionTestFailed'));
      }
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, t('ControllersStep.errors.connectionTestFailed')));
    } finally {
      setTesting(false);
    }
  };

  const handleProbeAndBindSites = async () => {
    if (!testResult?.success) {
      setError(t('ControllersStep.errors.testFirst'));
      return;
    }

    if (!supportsMultiSite) {
      // Skip site binding for non-multi-site controllers
      await handleAdd();
      return;
    }

    setProbingRemoteSites(true);
    setError(null);
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const probePayload: any = {
        controller_type: formData.adapter_id,
        host: formData.host || 'cloud',
        port: 443,
        username: formData.username,
        password: formData.password,
        verify_ssl: formData.verify_ssl,
        connection_mode: formData.connection_mode,
        client_id: formData.client_id,
        client_secret: formData.client_secret,
        omada_id: formData.omada_id,
        cloud_region: formData.cloud_region,
      };
      const result = await setupApi.probeRemoteSites(probePayload);
      setRemoteSites(result.remote_sites || []);
      // Also update freesdn sites from probe response
      if (result.freesdn_sites?.length) {
        setFreesdnSites(result.freesdn_sites);
      }
      // Initialize empty mappings
      const initialMappings: Record<string, string> = {};
      for (const rs of result.remote_sites || []) {
        initialMappings[rs.id] = '';
      }
      setFormData(prev => ({ ...prev, site_mappings: initialMappings }));
      setFormStep('site-binding');
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, t('ControllersStep.errors.probeFailed')));
    } finally {
      setProbingRemoteSites(false);
    }
  };

  const handleSiteMappingChange = (omadaSiteId: string, freesdnSiteId: string) => {
    setFormData(prev => ({
      ...prev,
      site_mappings: { ...prev.site_mappings, [omadaSiteId]: freesdnSiteId },
    }));
  };

  const handleAdd = async () => {
    if (!testResult?.success) {
      setError(t('ControllersStep.errors.testFirst'));
      return;
    }
    
    setSubmitting(true);
    setError(null);
    
    try {
      const payload = { ...formData };
      if (payload.connection_mode === 'cloud' && !payload.host) {
        payload.host = 'cloud';
      }
      // Filter out empty site mappings
      const activeMappings: Record<string, string> = {};
      for (const [omadaId, freesdnId] of Object.entries(payload.site_mappings || {})) {
        if (freesdnId && freesdnId !== '__skip__') {
          activeMappings[omadaId] = freesdnId;
        }
      }
      payload.site_mappings = activeMappings;
      // Use first mapped site as default if not set
      if (!payload.site_id && Object.values(activeMappings).length > 0) {
        payload.site_id = Object.values(activeMappings)[0];
      }
      // Fall back to the default site created during org step
      if (!payload.site_id && siteId) {
        payload.site_id = siteId;
      }

      const response = await setupApi.addController(payload);
      
      if (response.success) {
        addController(testResult.devices_found || 0);
        setAddedControllers(prev => [...prev, {
          name: formData.name,
          host: formData.host || (formData.cloud_region ? t('ControllersStep.regionCloud', { region: formData.cloud_region }) : t('ControllersStep.cloud')),
          adapter_id: formData.adapter_id,
          devices_found: testResult.devices_found || 0,
        }]);
        
        // Reset form
        setFormData({
          adapter_id: '',
          name: '',
          host: '',
          username: '',
          password: '',
          verify_ssl: true,
          site_id: '',
          connection_mode: 'local',
          client_id: '',
          client_secret: '',
          omada_id: '',
          cloud_region: '',
          site_mappings: {},
        });
        setTestResult(null);
        setShowForm(false);
        setFormStep('connection');
        setRemoteSites([]);
      } else {
        setError(response.error || t('ControllersStep.errors.addFailed'));
      }
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, t('ControllersStep.errors.addFailed')));
    } finally {
      setSubmitting(false);
    }
  };

  const selectedType = (controllerTypes ?? []).find(ct => ct.adapter_id === formData.adapter_id);

  if (loading) {
    return (
      <Card>
        <CardContent noOffset className="py-12 flex items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="flex flex-col min-h-full">
      <div className="flex-1 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">{t('ControllersStep.title')}</h1>
        <p className="text-muted-foreground mt-1">
          {t('ControllersStep.subtitle')}
        </p>
      </div>

      {/* Added Controllers */}
      {addedControllers.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-lg">{t('ControllersStep.addedControllers')}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {addedControllers.map((controller, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between p-3 rounded-lg bg-accent/50"
                >
                  <div className="flex items-center gap-3">
                    <CheckCircle2 className="h-5 w-5 text-green-500" />
                    <div>
                      <p className="font-medium">{controller.name}</p>
                      <p className="text-sm text-muted-foreground">{controller.host}</p>
                    </div>
                  </div>
                  <Badge variant="secondary">
                    {t('ControllersStep.devicesCount', { count: controller.devices_found })}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Add Controller Form */}
      {showForm ? (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {formStep === 'connection' ? (
                <>
                  <Network className="h-5 w-5" />
                  {t('ControllersStep.form.newController')}
                </>
              ) : (
                <>
                  <MapPin className="h-5 w-5" />
                  {t('ControllersStep.form.bindSites')}
                </>
              )}
            </CardTitle>
            <CardDescription>
              {formStep === 'connection'
                ? t('ControllersStep.form.connectionDescription')
                : t('ControllersStep.form.bindSitesDescription')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {formStep === 'connection' && (
                <>
                  <div className="space-y-2">
                    <Label>{t('ControllersStep.fields.controllerType')}</Label>
                    <Select
                      value={formData.adapter_id}
                      onValueChange={(value) => handleChange('adapter_id', value)}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder={t('ControllersStep.fields.controllerTypePlaceholder')} />
                      </SelectTrigger>
                      <SelectContent>
                        {(controllerTypes ?? []).map((type) => (
                          <SelectItem key={type.adapter_id} value={type.adapter_id}>
                            <div className="flex flex-col">
                              <span>{type.name}</span>
                              <span className="text-xs text-muted-foreground">{type.vendor}</span>
                            </div>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    {selectedType && (
                      <p className="text-xs text-muted-foreground">{selectedType.description}</p>
                    )}
                  </div>

                  {/* Connection Mode Toggle (Omada cloud support) */}
                  {showCloudToggle && (
                    <div className="space-y-2">
                      <Label>{t('ControllersStep.fields.connectionMode')}</Label>
                      <div className="grid grid-cols-2 gap-2">
                        <button
                          type="button"
                          className={`flex items-center justify-center gap-2 rounded-md border p-3 text-sm transition-colors ${
                            !isCloudMode
                              ? 'border-primary bg-primary/10 text-primary font-medium'
                              : 'border-border hover:bg-accent'
                          }`}
                          onClick={() => handleChange('connection_mode', 'local')}
                        >
                          <Monitor className="h-4 w-4" />
                          {t('ControllersStep.fields.modeLocal')}
                        </button>
                        <button
                          type="button"
                          className={`flex items-center justify-center gap-2 rounded-md border p-3 text-sm transition-colors ${
                            isCloudMode
                              ? 'border-primary bg-primary/10 text-primary font-medium'
                              : 'border-border hover:bg-accent'
                          }`}
                          onClick={() => handleChange('connection_mode', 'cloud')}
                        >
                          <Cloud className="h-4 w-4" />
                          {t('ControllersStep.fields.modeCloud')}
                        </button>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        {isCloudMode
                          ? t('ControllersStep.fields.modeCloudHint')
                          : t('ControllersStep.fields.modeLocalHint')}
                      </p>
                    </div>
                  )}

                  <div className="space-y-2">
                    <Label htmlFor="name">{t('ControllersStep.fields.displayName')}</Label>
                    <Input
                      id="name"
                      placeholder={t('ControllersStep.fields.displayNamePlaceholder')}
                      value={formData.name}
                      onChange={(e) => handleChange('name', e.target.value)}
                    />
                  </div>

                  {/* LOCAL MODE FIELDS */}
                  {!isCloudMode && (
                    <>
                      <div className="space-y-2">
                        <Label htmlFor="host">{t('ControllersStep.fields.host')}</Label>
                        <Input
                          id="host"
                          placeholder="https://192.168.1.1:8043"
                          value={formData.host}
                          onChange={(e) => handleChange('host', e.target.value)}
                        />
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div className="space-y-2">
                          <Label htmlFor="username">{t('ControllersStep.fields.username')}</Label>
                          <Input
                            id="username"
                            placeholder={t('ControllersStep.fields.usernamePlaceholder')}
                            value={formData.username}
                            onChange={(e) => handleChange('username', e.target.value)}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="password">{t('ControllersStep.fields.password')}</Label>
                          <Input
                            id="password"
                            type="password"
                            placeholder="••••••••"
                            value={formData.password}
                            onChange={(e) => handleChange('password', e.target.value)}
                          />
                        </div>
                      </div>
                    </>
                  )}

                  {/* CLOUD MODE FIELDS */}
                  {isCloudMode && (
                    <>
                      <div className="space-y-2">
                        <Label htmlFor="cloud_region">{t('ControllersStep.fields.cloudRegion')}</Label>
                        <Select
                          value={formData.cloud_region || ''}
                          onValueChange={(value) => handleChange('cloud_region', value)}
                        >
                          <SelectTrigger>
                            <SelectValue placeholder={t('ControllersStep.fields.cloudRegionPlaceholder')} />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="use1">{t('ControllersStep.fields.regionUsEast')}</SelectItem>
                            <SelectItem value="euw1">{t('ControllersStep.fields.regionEuWest')}</SelectItem>
                            <SelectItem value="aps1">{t('ControllersStep.fields.regionAsiaPacific')}</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <div className="space-y-2">
                        <Label htmlFor="client_id">{t('ControllersStep.fields.clientId')}</Label>
                        <Input
                          id="client_id"
                          placeholder={t('ControllersStep.fields.clientIdPlaceholder')}
                          value={formData.client_id || ''}
                          onChange={(e) => handleChange('client_id', e.target.value)}
                        />
                      </div>

                      <div className="space-y-2">
                        <Label htmlFor="client_secret">{t('ControllersStep.fields.clientSecret')}</Label>
                        <Input
                          id="client_secret"
                          type="password"
                          placeholder="••••••••"
                          value={formData.client_secret || ''}
                          onChange={(e) => handleChange('client_secret', e.target.value)}
                        />
                      </div>

                      <div className="space-y-2">
                        <Label htmlFor="omada_id">{t('ControllersStep.fields.omadaId')}</Label>
                        <Input
                          id="omada_id"
                          placeholder={t('ControllersStep.fields.omadaIdPlaceholder')}
                          value={formData.omada_id || ''}
                          onChange={(e) => handleChange('omada_id', e.target.value)}
                        />
                        <p className="text-xs text-muted-foreground">
                          {t('ControllersStep.fields.omadaIdHintBefore')}<code className="text-xs">omadacId</code>{t('ControllersStep.fields.omadaIdHintAfter')}
                        </p>
                      </div>
                    </>
                  )}

                  {/* Site ID for non-multi-site controllers */}
                  {!supportsMultiSite && (
                    <div className="space-y-2">
                      <Label htmlFor="site_id">{t('ControllersStep.fields.siteId')}</Label>
                      <Input
                        id="site_id"
                        placeholder={t('ControllersStep.fields.siteIdPlaceholder')}
                        value={formData.site_id}
                        onChange={(e) => handleChange('site_id', e.target.value)}
                      />
                    </div>
                  )}

                  <div className="flex items-center space-x-2">
                    <Switch
                      id="verify_ssl"
                      checked={formData.verify_ssl}
                      onCheckedChange={(checked) => handleChange('verify_ssl', checked)}
                    />
                    <Label htmlFor="verify_ssl" className="font-normal">
                      {t('ControllersStep.fields.verifySsl')}
                    </Label>
                  </div>

                  {/* Test Result */}
                  {testResult && (
                    <div className={`p-3 rounded-lg ${
                      testResult.success 
                        ? 'bg-green-500/10 border border-green-500/20' 
                        : 'bg-destructive/10 border border-destructive/20'
                    }`}>
                      <div className="flex items-center gap-2">
                        {testResult.success ? (
                          <CheckCircle2 className="h-5 w-5 text-green-500" />
                        ) : (
                          <XCircle className="h-5 w-5 text-destructive" />
                        )}
                        <span className={testResult.success ? 'text-green-600 dark:text-green-400' : 'text-destructive'}>
                          {testResult.success
                            ? t('ControllersStep.testSuccess', { count: testResult.devices_found })
                            : testResult.error}
                        </span>
                      </div>
                    </div>
                  )}

                  {error && !testResult && (
                    <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
                      <p className="text-destructive text-sm whitespace-pre-line">{error}</p>
                    </div>
                  )}

                  <div className="flex gap-2 pt-2">
                    <Button
                      variant="outline"
                      onClick={handleTest}
                      disabled={testing || submitting || probingRemoteSites}
                    >
                      {testing && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                      <TestTube className="mr-2 h-4 w-4" />
                      {t('ControllersStep.actions.testConnection')}
                    </Button>
                    {supportsMultiSite ? (
                      <Button
                        onClick={handleProbeAndBindSites}
                        disabled={!testResult?.success || submitting || probingRemoteSites}
                      >
                        {probingRemoteSites && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        <MapPin className="mr-2 h-4 w-4" />
                        {probingRemoteSites ? t('ControllersStep.actions.probingSites') : t('ControllersStep.actions.nextBindSites')}
                      </Button>
                    ) : (
                      <Button
                        onClick={handleAdd}
                        disabled={!testResult?.success || submitting}
                      >
                        {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        <Plus className="mr-2 h-4 w-4" />
                        {t('ControllersStep.actions.addController')}
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      onClick={() => {
                        setShowForm(false);
                        setTestResult(null);
                        setError(null);
                        setFormStep('connection');
                        setRemoteSites([]);
                      }}
                    >
                      {t('ControllersStep.actions.cancel')}
                    </Button>
                  </div>
                </>
              )}

              {/* ============ SITE BINDING STEP ============ */}
              {formStep === 'site-binding' && (
                <>
                  <p className="text-sm text-muted-foreground">
                    {t('ControllersStep.binding.intro.before')}<strong>{remoteSites.length}</strong>{t('ControllersStep.binding.intro.after', { count: remoteSites.length })}
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
                          value={formData.site_mappings?.[rs.id] || '__skip__'}
                          onValueChange={(value) => handleSiteMappingChange(rs.id, value === '__skip__' ? '' : value)}
                        >
                          <SelectTrigger className="h-9">
                            <SelectValue placeholder={t('ControllersStep.binding.selectSitePlaceholder')} />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="__skip__">
                              <span className="text-muted-foreground">{t('ControllersStep.binding.skipOption')}</span>
                            </SelectItem>
                            {freesdnSites.map((site) => (
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
                      {t('ControllersStep.binding.noSites')}
                    </div>
                  )}

                  {error && (
                    <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
                      <p className="text-destructive text-sm whitespace-pre-line">{error}</p>
                    </div>
                  )}

                  <div className="flex gap-2 pt-2">
                    <Button
                      variant="outline"
                      onClick={() => { setFormStep('connection'); setError(null); }}
                      disabled={submitting}
                    >
                      <ChevronLeft className="mr-1 h-4 w-4" />
                      {t('ControllersStep.actions.back')}
                    </Button>
                    <Button
                      onClick={handleAdd}
                      disabled={submitting}
                    >
                      {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                      <Plus className="mr-2 h-4 w-4" />
                      {t('ControllersStep.actions.addController')}
                    </Button>
                  </div>
                </>
              )}
            </div>
          </CardContent>
        </Card>
      ) : (
        <Card className="border-dashed">
          <CardContent noOffset className="py-8 text-center">
            <Network className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
            <p className="text-muted-foreground mb-4">
              {addedControllers.length > 0
                ? t('ControllersStep.empty.addAnother')
                : t('ControllersStep.empty.none')}
            </p>
            <Button onClick={() => setShowForm(true)}>
              <Plus className="mr-2 h-4 w-4" />
              {t('ControllersStep.actions.addController')}
            </Button>
          </CardContent>
        </Card>
      )}

      <div className="p-4 bg-accent/50 rounded-lg">
        <p className="text-sm text-muted-foreground">
          <strong>{t('ControllersStep.note.label')}</strong> {t('ControllersStep.note.text')}
        </p>
      </div>

      </div>

      <div className="sticky bottom-0 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80 border-t border-border/50 pt-4 pb-4 -mx-1 px-1 mt-6">
        <div className="flex justify-between">
          <Button variant="outline" onClick={onPrevious}>
            <ChevronLeft className="mr-2 h-4 w-4" />
            {t('ControllersStep.actions.previous')}
          </Button>
          <Button onClick={onNext}>
            {addedControllers.length > 0 ? t('ControllersStep.actions.continue') : t('ControllersStep.actions.skipForNow')}
            <ChevronRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}
