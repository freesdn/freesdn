// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Setup Wizard: Database Step
 */
import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { setupApi, type DatabaseCheckResponse } from '@/lib/setup-api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { 
  CheckCircle2, 
  XCircle, 
  Loader2, 
  Database,
  ChevronRight,
  ChevronLeft,
  RefreshCw,
} from 'lucide-react';

interface DatabaseStepProps {
  onNext: () => void;
  onPrevious: () => void;
}

export function DatabaseStep({ onNext, onPrevious }: DatabaseStepProps) {
  const { t } = useTranslation('setup');
  const [loading, setLoading] = useState(true);
  const [migrating, setMigrating] = useState(false);
  const [data, setData] = useState<DatabaseCheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await setupApi.checkDatabase();
      setData(response);
    } catch (_err) {
      setError(t('DatabaseStep.errors.checkFailed'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleMigrate = async () => {
    setMigrating(true);
    setError(null);
    try {
      await setupApi.runMigrations();
      await loadData();
    } catch (_err) {
      setError(t('DatabaseStep.errors.migrationsFailed'));
    } finally {
      setMigrating(false);
    }
  };

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
        <h1 className="text-2xl font-bold">{t('DatabaseStep.title')}</h1>
        <p className="text-muted-foreground mt-1">
          {t('DatabaseStep.subtitle')}
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-5 w-5" />
                {t('DatabaseStep.status.heading')}
              </CardTitle>
              <CardDescription>
                {t('DatabaseStep.status.description')}
              </CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={loadData}>
              <RefreshCw className="h-4 w-4 mr-1" />
              {t('DatabaseStep.actions.refresh')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {error && !data && (
            <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-lg mb-4">
              <p className="text-destructive">{error}</p>
            </div>
          )}

          {data && (
            <div className="space-y-4">
              {/* Connection Status */}
              <div className="flex items-center justify-between p-3 rounded-lg bg-accent/50">
                <div className="flex items-center gap-3">
                  {data.connected ? (
                    <CheckCircle2 className="h-5 w-5 text-green-500" />
                  ) : (
                    <XCircle className="h-5 w-5 text-destructive" />
                  )}
                  <div>
                    <p className="font-medium">{t('DatabaseStep.connection.label')}</p>
                    <p className="text-sm text-muted-foreground">
                      {data.connected ? t('DatabaseStep.connection.connected') : t('DatabaseStep.connection.failed')}
                    </p>
                  </div>
                </div>
                <Badge variant={data.connected ? 'default' : 'destructive'}>
                  {data.connected ? t('DatabaseStep.badges.ok') : t('DatabaseStep.badges.error')}
                </Badge>
              </div>

              {data.connected && (
                <>
                  {/* Database Type */}
                  <div className="flex items-center justify-between p-3 rounded-lg bg-accent/50">
                    <div className="flex items-center gap-3">
                      <CheckCircle2 className="h-5 w-5 text-green-500" />
                      <div>
                        <p className="font-medium">{t('DatabaseStep.databaseType.label')}</p>
                        <p className="text-sm text-muted-foreground">
                          {data.database_version
                            ? (data.database_version.match(/^(PostgreSQL\s+\d+\.\d+)/) || [])[1] || data.database_version
                            : data.database_type}
                        </p>
                      </div>
                    </div>
                    <Badge variant="default">
                      {(data.database_type ?? 'postgresql').charAt(0).toUpperCase() + (data.database_type ?? 'postgresql').slice(1)}
                    </Badge>
                  </div>

                  {/* TimescaleDB */}
                  <div className="flex items-center justify-between p-3 rounded-lg bg-accent/50">
                    <div className="flex items-center gap-3">
                      {data.timescale_enabled ? (
                        <CheckCircle2 className="h-5 w-5 text-green-500" />
                      ) : (
                        <XCircle className="h-5 w-5 text-destructive" />
                      )}
                      <div>
                        <p className="font-medium">TimescaleDB</p>
                        <p className="text-sm text-muted-foreground">
                          {data.timescale_enabled
                            ? t('DatabaseStep.timescale.enabledDetail', {
                                version: data.timescale_version ?? '?',
                                location: data.timescale_location === 'logdb'
                                  ? t('DatabaseStep.timescale.locationLog')
                                  : t('DatabaseStep.timescale.locationMain'),
                              })
                            : t('DatabaseStep.timescale.required')}
                        </p>
                      </div>
                    </div>
                    <Badge variant={data.timescale_enabled ? 'default' : 'destructive'}>
                      {data.timescale_enabled ? t('DatabaseStep.badges.enabled') : t('DatabaseStep.badges.required')}
                    </Badge>
                  </div>

                  {/* Log Database (mandatory) */}
                  <div className="flex items-center justify-between p-3 rounded-lg bg-accent/50">
                    <div className="flex items-center gap-3">
                      {data.logdb_connected ? (
                        <CheckCircle2 className="h-5 w-5 text-green-500" />
                      ) : (
                        <XCircle className="h-5 w-5 text-destructive" />
                      )}
                      <div>
                        <p className="font-medium">{t('DatabaseStep.logDatabase.label')}</p>
                        <p className="text-sm text-muted-foreground">
                          {data.logdb_connected
                            ? t('DatabaseStep.logDatabase.connectedDetail')
                            : t('DatabaseStep.logDatabase.required')}
                        </p>
                      </div>
                    </div>
                    <Badge variant={data.logdb_connected ? 'default' : 'destructive'}>
                      {data.logdb_connected ? t('DatabaseStep.badges.connected') : t('DatabaseStep.badges.required')}
                    </Badge>
                  </div>

                  {/* Migrations */}
                  <div className="flex items-center justify-between p-3 rounded-lg bg-accent/50">
                    <div className="flex items-center gap-3">
                      {data.schema_current ? (
                        <CheckCircle2 className="h-5 w-5 text-green-500" />
                      ) : (
                        <XCircle className="h-5 w-5 text-yellow-500" />
                      )}
                      <div>
                        <p className="font-medium">{t('DatabaseStep.migrations.label')}</p>
                        <p className="text-sm text-muted-foreground">
                          {data.schema_current
                            ? t('DatabaseStep.migrations.upToDate')
                            : t('DatabaseStep.migrations.countDetail', {
                                applied: data.migrations_applied ?? 0,
                                pending: data.migrations_pending ?? 0,
                              })}
                        </p>
                      </div>
                    </div>
                    {data.migrations_pending ? (
                      <Button
                        size="sm"
                        onClick={handleMigrate}
                        disabled={migrating}
                      >
                        {migrating && <Loader2 className="h-4 w-4 mr-1 animate-spin" />}
                        {migrating ? t('DatabaseStep.migrations.running') : t('DatabaseStep.actions.runMigrations')}
                      </Button>
                    ) : (
                      <Badge variant="default">{t('DatabaseStep.badges.upToDate')}</Badge>
                    )}
                  </div>
                </>
              )}

              {migrating && (
                <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                  <div className="flex items-center gap-3">
                    <Loader2 className="h-5 w-5 text-blue-500 animate-spin flex-shrink-0" />
                    <div>
                      <p className="text-sm font-medium text-blue-600 dark:text-blue-400">
                        {t('DatabaseStep.migrations.runningBanner.title')}
                      </p>
                      <p className="text-xs text-muted-foreground mt-0.5">
                        {t('DatabaseStep.migrations.runningBanner.description')}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {data.error && (
                <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-lg">
                  <p className="text-destructive text-sm">{data.error}</p>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      </div>

      <div className="sticky bottom-0 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80 border-t border-border/50 pt-4 pb-4 -mx-1 px-1 mt-6">
        <div className="flex justify-between">
          <Button variant="outline" onClick={onPrevious}>
            <ChevronLeft className="mr-2 h-4 w-4" />
            {t('DatabaseStep.actions.previous')}
          </Button>
          <Button
            onClick={onNext}
            disabled={!data?.connected || !data?.logdb_connected}
          >
            {t('DatabaseStep.actions.continue')}
            <ChevronRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}
