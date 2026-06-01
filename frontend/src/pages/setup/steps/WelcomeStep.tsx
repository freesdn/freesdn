// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Setup Wizard: Welcome Step
 */
import { useState, useEffect, version as reactVersion } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { setupApi, type WelcomeResponse, type SystemRequirement } from '@/lib/setup-api';
import { useSetupStore } from '@/stores/setupStore';
import { FRONTEND_VERSIONS } from '@/lib/build-info';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  CheckCircle2,
  XCircle,
  Loader2,
  Network,
  ChevronRight,
  Info,
  ChevronDown,
  Container,
  Server,
  Monitor,
  Upload,
  AlertTriangle,
} from 'lucide-react';

interface WelcomeStepProps {
  onNext: () => void;
}

export function WelcomeStep({ onNext }: WelcomeStepProps) {
  const { t } = useTranslation('setup');
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<WelcomeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const setEnvironment = useSetupStore((s) => s.setEnvironment);

  // Restore-from-backup branch (the bare-metal "I already have a .fsdnvault" path).
  const [restoreOpen, setRestoreOpen] = useState(false);
  const [restoreFile, setRestoreFile] = useState<File | null>(null);
  const [restorePass, setRestorePass] = useState('');
  const [restoring, setRestoring] = useState(false);
  const [restoreError, setRestoreError] = useState<string | null>(null);

  const handleRestore = async () => {
    if (!restoreFile || restorePass.length < 12) return;
    setRestoring(true);
    setRestoreError(null);
    try {
      await setupApi.restoreFromVault(restoreFile, restorePass);
      // The restored super_admin completes setup — go log in with the OLD credentials.
      navigate('/login');
    } catch (err: any) {
      setRestoreError(
        err?.response?.data?.detail || t('WelcomeStep.restore.failed'),
      );
    } finally {
      setRestoring(false);
    }
  };

  useEffect(() => {
    const loadData = async () => {
      try {
        const response = await setupApi.getWelcome();
        setData(response);
        if (response.environment) {
          setEnvironment(response.environment);
        }
      } catch (_err) {
        setError(t('WelcomeStep.errors.checkFailed'));
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, [setEnvironment, t]);

  if (loading) {
    return (
      <Card>
        <CardContent noOffset className="py-12 flex items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    );
  }

  if (error || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-destructive">{t('WelcomeStep.errors.title')}</CardTitle>
        </CardHeader>
        <CardContent>
          <p>{error || t('WelcomeStep.errors.unknown')}</p>
          <Button className="mt-4" onClick={() => window.location.reload()}>
            {t('WelcomeStep.actions.retry')}
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="flex flex-col min-h-full">
      <div className="flex-1 space-y-6">
      <div className="text-center">
        <div className="h-16 w-16 rounded-2xl bg-gradient-to-br from-primary to-primary/80 flex items-center justify-center shadow-lg shadow-primary/20 mx-auto mb-4">
          <Network className="h-9 w-9 text-primary-foreground" />
        </div>
        <h1 className="text-3xl font-bold">{t('WelcomeStep.hero.title', { appName: data.app_name })}</h1>
        <p className="text-muted-foreground mt-2">
          {t('WelcomeStep.hero.subtitle')}
        </p>
        <Badge variant="secondary" className="mt-2">
          {t('WelcomeStep.hero.version', { version: data.app_version })}
        </Badge>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t('WelcomeStep.requirements.title')}</CardTitle>
          <CardDescription>
            {t('WelcomeStep.requirements.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {(data.requirements ?? []).map((req: SystemRequirement, index: number) => (
              <div 
                key={index}
                className="flex items-center justify-between p-3 rounded-lg bg-accent/50"
              >
                <div className="flex items-center gap-3">
                  {req.passed ? (
                    <CheckCircle2 className="h-5 w-5 text-green-500" />
                  ) : (
                    <XCircle className="h-5 w-5 text-destructive" />
                  )}
                  <div>
                    <p className="font-medium">{req.name}</p>
                    <p className="text-sm text-muted-foreground">
                      {t('WelcomeStep.requirements.required', { value: req.required })}
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  <p className={req.passed ? 'text-green-500' : 'text-destructive'}>
                    {req.actual}
                  </p>
                  {req.message && (
                    <p className="text-xs text-muted-foreground">{req.message}</p>
                  )}
                </div>
              </div>
            ))}
          </div>

          {data.all_requirements_met ? (
            <div className="mt-6 p-4 bg-success/10 border border-success/20 rounded-lg">
              <p className="text-success font-medium inline-flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                {t('WelcomeStep.requirements.allMet')}
              </p>
            </div>
          ) : (
            <div className="mt-6 p-4 bg-destructive/10 border border-destructive/20 rounded-lg">
              <p className="text-destructive font-medium inline-flex items-center gap-2">
                <XCircle className="h-4 w-4 shrink-0" />
                {t('WelcomeStep.requirements.notMet')}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      <details className="group">
        <summary className="flex items-center gap-2 cursor-pointer text-sm text-muted-foreground hover:text-foreground transition-colors select-none">
          <ChevronDown className="h-4 w-4 transition-transform group-open:rotate-180" />
          <Info className="h-4 w-4" />
          {t('WelcomeStep.stack.title')}
        </summary>
        <div className="mt-2 space-y-3">
          {/* Backend Stack */}
          {data.stack_info && data.stack_info.length > 0 && (
            <Card>
              <CardHeader className="py-3 px-4">
                <div className="flex items-center gap-2 text-sm font-medium">
                  <Server className="h-4 w-4 text-muted-foreground" />
                  {t('WelcomeStep.stack.backend')}
                </div>
              </CardHeader>
              <CardContent className="px-4 pb-3 pt-0">
                <div className="grid grid-cols-2 gap-x-8 gap-y-1 text-sm">
                  {data.stack_info.map((item, i) => (
                    <div key={i} className="flex justify-between py-0.5">
                      <span className="text-muted-foreground">{item.name}</span>
                      <span className="font-mono text-xs tabular-nums">{item.version}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Frontend Stack */}
          <Card>
            <CardHeader className="py-3 px-4">
              <div className="flex items-center gap-2 text-sm font-medium">
                <Monitor className="h-4 w-4 text-muted-foreground" />
                {t('WelcomeStep.stack.frontend')}
              </div>
            </CardHeader>
            <CardContent className="px-4 pb-3 pt-0">
              <div className="grid grid-cols-2 gap-x-8 gap-y-1 text-sm">
                {[
                  { name: 'Node.js', version: FRONTEND_VERSIONS?.node },
                  { name: 'npm', version: FRONTEND_VERSIONS?.npm },
                  { name: 'React', version: reactVersion },
                  { name: 'React Router', version: FRONTEND_VERSIONS?.['react-router'] },
                  { name: 'TypeScript', version: FRONTEND_VERSIONS?.typescript },
                  { name: 'Vite', version: FRONTEND_VERSIONS?.vite },
                  { name: 'TailwindCSS', version: FRONTEND_VERSIONS?.tailwindcss },
                  { name: 'Zustand', version: FRONTEND_VERSIONS?.zustand },
                ].map((item, i) => (
                  <div key={i} className="flex justify-between py-0.5">
                    <span className="text-muted-foreground">{item.name}</span>
                    <span className="font-mono text-xs tabular-nums">{item.version}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Docker Services */}
          {data.docker_services && data.docker_services.length > 0 && (
            <Card>
              <CardHeader className="py-3 px-4">
                <div className="flex items-center gap-2 text-sm font-medium">
                  <Container className="h-4 w-4 text-muted-foreground" />
                  {t('WelcomeStep.stack.dockerServices')}
                </div>
              </CardHeader>
              <CardContent className="px-4 pb-3 pt-0">
                <div className="grid grid-cols-2 gap-x-8 gap-y-1 text-sm">
                  {data.docker_services.map((svc, i) => (
                    <div key={i} className="flex justify-between py-0.5">
                      <span className="text-muted-foreground">{svc.name}</span>
                      <span className="flex items-center gap-1.5">
                        {svc.reachable ? (
                          <CheckCircle2 className="h-3 w-3 text-green-500" />
                        ) : (
                          <XCircle className="h-3 w-3 text-muted-foreground/50" />
                        )}
                        <span className="font-mono text-xs tabular-nums">
                          {svc.reachable ? svc.host : t('WelcomeStep.stack.unreachable')}
                        </span>
                      </span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </details>

      {/* Restore-from-backup branch — migrate to this fresh box from a .fsdnvault */}
      <Card>
        <CardHeader className="py-3 px-4">
          <button
            type="button"
            onClick={() => setRestoreOpen((o) => !o)}
            className="flex items-center gap-2 text-sm font-medium w-full text-left"
          >
            <Upload className="h-4 w-4 text-muted-foreground" />
            {t('WelcomeStep.restore.toggle')}
            <ChevronDown
              className={
                restoreOpen
                  ? 'h-4 w-4 ml-auto rotate-180 transition-transform'
                  : 'h-4 w-4 ml-auto transition-transform'
              }
            />
          </button>
        </CardHeader>
        {restoreOpen && (
          <CardContent className="px-4 pb-4 pt-0 space-y-3">
            <p className="text-sm text-muted-foreground">{t('WelcomeStep.restore.help')}</p>
            <div className="space-y-2">
              <Label htmlFor="restore-file">{t('WelcomeStep.restore.fileLabel')}</Label>
              <Input
                id="restore-file"
                type="file"
                accept=".fsdnvault"
                onChange={(e) => setRestoreFile(e.target.files?.[0] ?? null)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="restore-pass">{t('WelcomeStep.restore.passLabel')}</Label>
              <Input
                id="restore-pass"
                type="password"
                autoComplete="off"
                value={restorePass}
                onChange={(e) => setRestorePass(e.target.value)}
                placeholder={t('WelcomeStep.restore.passPlaceholder')}
              />
            </div>
            {restoreError && (
              <div className="text-sm text-destructive flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
                <span>{restoreError}</span>
              </div>
            )}
            <Button
              onClick={handleRestore}
              disabled={!restoreFile || restorePass.length < 12 || restoring}
              className="w-full"
            >
              {restoring ? (
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
              ) : (
                <Upload className="h-4 w-4 mr-2" />
              )}
              {t('WelcomeStep.restore.submit')}
            </Button>
          </CardContent>
        )}
      </Card>

      </div>

      <div className="sticky bottom-0 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80 border-t border-border/50 pt-4 pb-4 -mx-1 px-1 mt-6">
        <div className="flex justify-end">
          <Button
            onClick={onNext}
            disabled={!data.can_proceed}
            size="lg"
          >
            {t('WelcomeStep.actions.continue')}
            <ChevronRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}
