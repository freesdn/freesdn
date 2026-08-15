// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Setup Wizard: Complete Step
 */
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { setupApi, type SetupCompleteResponse } from '@/lib/setup-api';
import { getApiErrorMessage, systemApi } from '@/lib/api';
import { useSetupStore } from '@/stores/setupStore';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Badge } from '@/components/ui/badge';
import { 
  Loader2, 
  PartyPopper,
  CheckCircle2,
  ArrowRight,
  Radar,
  Building2,
  Shield,
  Puzzle,
  Network,
  Database,
  Eye,
  Pencil,
} from 'lucide-react';

export function CompleteStep() {
  const { t } = useTranslation('setup');
  const navigate = useNavigate();
  const {
    adminEmail,
    organizationName,
    organizationId,
    siteId,
    enabledModules,
    accessMode,
    controllersAdded,
    totalDevices,
    availableModules,
    reset: resetStore,
  } = useSetupStore();
  
  const [completing, setCompleting] = useState(false);
  const [completed, setCompleted] = useState(false);
  const [progressMessage, setProgressMessage] = useState('');
  const [installSampleData, setInstallSampleData] = useState(false);
  const [startDiscovery, setStartDiscovery] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [monitorWarning, setMonitorWarning] = useState<string | null>(null);
  const [result, setResult] = useState<SetupCompleteResponse | null>(null);

  const handleComplete = async () => {
    setCompleting(true);
    setError(null);
    setProgressMessage(t('CompleteStep.progress.finalizing'));

    try {
      if (installSampleData) {
        setProgressMessage(t('CompleteStep.progress.installingSampleData'));
      }
      if (startDiscovery) {
        setProgressMessage(installSampleData
          ? t('CompleteStep.progress.installingAndDiscovery')
          : t('CompleteStep.progress.startingDiscovery'));
      }

      const response = await setupApi.completeSetup({
        install_sample_data: installSampleData,
        organization_id: organizationId || undefined,
        site_id: siteId || undefined,
        start_discovery: startDiscovery,
      });

      if (response.success) {
        // If the user picked "Monitor only" in the Access Mode step,
        // flip adapter read-only on now (post-completion, admin exists
        // and is authenticated). Non-fatal: the toggle is recoverable
        // in Settings, so a failure here surfaces a warning but does
        // not block finishing setup.
        if (accessMode === 'monitor') {
          setProgressMessage(t('CompleteStep.progress.enablingMonitorOnly'));
          try {
            await systemApi.setAdapterReadOnly(true);
          } catch (modeErr: unknown) {
            setMonitorWarning(
              getApiErrorMessage(modeErr, t('CompleteStep.errors.monitorOnlyFailed')),
            );
          }
        }
        setResult(response);
        setCompleted(true);
      } else {
        setError(response.error || t('CompleteStep.errors.failed'));
      }
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, t('CompleteStep.errors.failed')));
    } finally {
      setCompleting(false);
      setProgressMessage('');
    }
  };

  const handleGoToDashboard = () => {
    resetStore();
    navigate('/login');
  };

  const getModuleName = (id: string) => {
    return availableModules.find(m => m.id === id)?.name || id;
  };

  if (completed && result) {
    return (
      <div className="space-y-6">
        <div className="text-center">
          <div className="w-20 h-20 bg-green-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
            <CheckCircle2 className="h-10 w-10 text-green-500" />
          </div>
          <h1 className="text-3xl font-bold text-green-600 dark:text-green-400">
            {t('CompleteStep.done.heading')}
          </h1>
          <p className="text-muted-foreground mt-2">
            {t('CompleteStep.done.subtitle')}
          </p>
        </div>

        {monitorWarning && (
          <div className="p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
            <p className="text-sm text-yellow-700 dark:text-yellow-400">
              {t('CompleteStep.done.monitorOnlyWarning', { error: monitorWarning })}
            </p>
          </div>
        )}

        <Card>
          <CardHeader>
            <CardTitle>{t('CompleteStep.summary.title')}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="p-4 bg-accent/50 rounded-lg">
                <div className="flex items-center gap-2 text-muted-foreground mb-1">
                  <Shield className="h-4 w-4" />
                  <span className="text-sm">{t('CompleteStep.summary.adminAccount')}</span>
                </div>
                <p className="font-medium">{result.summary?.admin_email || adminEmail || '-'}</p>
              </div>
              <div className="p-4 bg-accent/50 rounded-lg">
                <div className="flex items-center gap-2 text-muted-foreground mb-1">
                  <Building2 className="h-4 w-4" />
                  <span className="text-sm">{t('CompleteStep.summary.organization')}</span>
                </div>
                <p className="font-medium">{result.summary?.organization_name || organizationName || '-'}</p>
              </div>
              <div className="p-4 bg-accent/50 rounded-lg">
                <div className="flex items-center gap-2 text-muted-foreground mb-1">
                  <Puzzle className="h-4 w-4" />
                  <span className="text-sm">{t('CompleteStep.summary.modulesEnabled')}</span>
                </div>
                <p className="font-medium">{result.summary?.enabled_modules?.length || 0}</p>
              </div>
              <div className="p-4 bg-accent/50 rounded-lg">
                <div className="flex items-center gap-2 text-muted-foreground mb-1">
                  <Network className="h-4 w-4" />
                  <span className="text-sm">{t('CompleteStep.summary.controllersAdded')}</span>
                </div>
                <p className="font-medium">
                  {result.summary?.controllers_added || 0}
                  {(result.summary?.total_devices || 0) > 0 && (
                    <span className="text-muted-foreground text-sm ml-1">
                      {t('CompleteStep.summary.devicesCount', { count: result.summary?.total_devices })}
                    </span>
                  )}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Button size="lg" className="w-full" onClick={handleGoToDashboard}>
          {t('CompleteStep.actions.goToLogin')}
          <ArrowRight className="ml-2 h-4 w-4" />
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="text-center">
        <PartyPopper className="h-16 w-16 text-primary mx-auto mb-4" />
        <h1 className="text-3xl font-bold">{t('CompleteStep.review.heading')}</h1>
        <p className="text-muted-foreground mt-2">
          {t('CompleteStep.review.subtitle')}
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t('CompleteStep.summary.title')}</CardTitle>
          <CardDescription>
            {t('CompleteStep.summary.description')}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Admin */}
          <div className="flex items-start gap-3 p-3 rounded-lg bg-accent/50">
            <Shield className="h-5 w-5 text-muted-foreground mt-0.5" />
            <div className="flex-1">
              <p className="font-medium">{t('CompleteStep.review.administrator')}</p>
              <p className="text-sm text-muted-foreground">{adminEmail}</p>
            </div>
            <CheckCircle2 className="h-5 w-5 text-green-500" />
          </div>

          {/* Organization */}
          <div className="flex items-start gap-3 p-3 rounded-lg bg-accent/50">
            <Building2 className="h-5 w-5 text-muted-foreground mt-0.5" />
            <div className="flex-1">
              <p className="font-medium">{t('CompleteStep.summary.organization')}</p>
              <p className="text-sm text-muted-foreground">{organizationName}</p>
            </div>
            <CheckCircle2 className="h-5 w-5 text-green-500" />
          </div>

          {/* Modules */}
          <div className="flex items-start gap-3 p-3 rounded-lg bg-accent/50">
            <Puzzle className="h-5 w-5 text-muted-foreground mt-0.5" />
            <div className="flex-1">
              <p className="font-medium">{t('CompleteStep.review.enabledModules')}</p>
              <div className="flex flex-wrap gap-1 mt-1">
                {enabledModules.map(id => (
                  <Badge key={id} variant="secondary" className="text-xs">
                    {getModuleName(id)}
                  </Badge>
                ))}
              </div>
            </div>
            <CheckCircle2 className="h-5 w-5 text-green-500" />
          </div>

          {/* Controllers */}
          <div className="flex items-start gap-3 p-3 rounded-lg bg-accent/50">
            <Network className="h-5 w-5 text-muted-foreground mt-0.5" />
            <div className="flex-1">
              <p className="font-medium">{t('CompleteStep.review.controllers')}</p>
              <p className="text-sm text-muted-foreground">
                {controllersAdded > 0
                  ? t('CompleteStep.review.controllersFound', { controllers: controllersAdded, devices: totalDevices })
                  : t('CompleteStep.review.noControllers')}
              </p>
            </div>
            <CheckCircle2 className="h-5 w-5 text-green-500" />
          </div>

          {/* Access mode */}
          <div className="flex items-start gap-3 p-3 rounded-lg bg-accent/50">
            {accessMode === 'monitor' ? (
              <Eye className="h-5 w-5 text-muted-foreground mt-0.5" />
            ) : (
              <Pencil className="h-5 w-5 text-muted-foreground mt-0.5" />
            )}
            <div className="flex-1">
              <p className="font-medium">{t('CompleteStep.review.accessMode')}</p>
              <p className="text-sm text-muted-foreground">
                {accessMode === 'monitor'
                  ? t('CompleteStep.review.accessModeMonitor')
                  : t('CompleteStep.review.accessModeManage')}
              </p>
            </div>
            <CheckCircle2 className="h-5 w-5 text-green-500" />
          </div>
        </CardContent>
      </Card>

      {/* Options */}
      <Card>
        <CardHeader>
          <CardTitle>{t('CompleteStep.options.title')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <label className="flex items-center gap-3 cursor-pointer">
            <Checkbox
              checked={installSampleData}
              onCheckedChange={(checked) => setInstallSampleData(!!checked)}
            />
            <div className="flex items-center gap-2">
              <Database className="h-4 w-4 text-muted-foreground" />
              <div>
                <span>{t('CompleteStep.options.installSampleData')}</span>
                <p className="text-xs text-muted-foreground">
                  {t('CompleteStep.options.installSampleDataHelp')}
                </p>
              </div>
            </div>
          </label>

          <label className="flex items-center gap-3 cursor-pointer">
            <Checkbox
              checked={startDiscovery}
              onCheckedChange={(checked) => setStartDiscovery(!!checked)}
            />
            <div className="flex items-center gap-2">
              <Radar className="h-4 w-4 text-muted-foreground" />
              <span>{t('CompleteStep.options.startDiscovery')}</span>
            </div>
          </label>

        </CardContent>
      </Card>

      {error && (
        <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      {completing && progressMessage && (
        <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg">
          <div className="flex items-center gap-3">
            <Loader2 className="h-5 w-5 text-blue-500 animate-spin flex-shrink-0" />
            <p className="text-sm font-medium text-blue-600 dark:text-blue-400">
              {progressMessage}
            </p>
          </div>
        </div>
      )}

      <Button
        size="lg"
        className="w-full"
        onClick={handleComplete}
        disabled={completing}
      >
        {completing && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
        {completing ? t('CompleteStep.actions.completing') : t('CompleteStep.actions.complete')}
        {!completing && <CheckCircle2 className="ml-2 h-4 w-4" />}
      </Button>
    </div>
  );
}
