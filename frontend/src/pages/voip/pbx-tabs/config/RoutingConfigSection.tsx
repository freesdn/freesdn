// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * RoutingConfigSection · call-flow routing config cards (outbound routes,
 * follow-me, time conditions, day/night controls) for the PBX Config tab.
 *
 * Pure render of `fullConfig` slices. Each Card is conditionally rendered
 * based on whether the corresponding array is non-empty.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { Route, Phone, Clock, Moon } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

export interface RoutingConfigSectionProps {
  fullConfig: any;
}

export function RoutingConfigSection({ fullConfig }: RoutingConfigSectionProps) {
  const { t } = useTranslation('voip');
  return (
    <>
      {/* Outbound Routes */}
      {(fullConfig.outbound_routes?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <Route className="h-4 w-4" /> {t('RoutingConfigSection.outboundRoutes.title', { count: fullConfig.outbound_routes.length })}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2 pr-4">{t('RoutingConfigSection.outboundRoutes.columns.name')}</th><th className="pb-2 pr-4">{t('RoutingConfigSection.outboundRoutes.columns.cid')}</th>
                  <th className="pb-2 pr-4">{t('RoutingConfigSection.outboundRoutes.columns.emergency')}</th><th className="pb-2 pr-4">{t('RoutingConfigSection.outboundRoutes.columns.sequence')}</th>
                </tr></thead>
                <tbody>
                  {fullConfig.outbound_routes.map((r: any, i: number) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-medium">{r.name || t('RoutingConfigSection.outboundRoutes.fallbackName', { index: i + 1 })}</td>
                      <td className="py-2 pr-4 font-mono text-xs">{r.outcid || '-'}</td>
                      <td className="py-2 pr-4">{r.emergency_route === 'YES' ? <Badge variant="destructive" className="text-[10px]">{t('RoutingConfigSection.outboundRoutes.emergencyBadge')}</Badge> : '-'}</td>
                      <td className="py-2 pr-4">{r.seq ?? '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Follow Me */}
      {(fullConfig.followme?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <Phone className="h-4 w-4" /> {t('RoutingConfigSection.followMe.title', { count: fullConfig.followme.length })}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="flex flex-wrap gap-2">
              {fullConfig.followme.map((fm: any, i: number) => (
                <Badge key={i} variant="outline" className="font-mono">
                  {t('RoutingConfigSection.followMe.extension', { ext: fm.ext || fm.grpnum || i })}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Day/Night Controls */}
      {(fullConfig.daynight?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <Moon className="h-4 w-4" /> {t('RoutingConfigSection.dayNight.title', { count: fullConfig.daynight.length })}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2 pr-4">{t('RoutingConfigSection.dayNight.columns.extension')}</th><th className="pb-2 pr-4">{t('RoutingConfigSection.dayNight.columns.destination')}</th><th className="pb-2 pr-4">{t('RoutingConfigSection.dayNight.columns.description')}</th>
                </tr></thead>
                <tbody>
                  {fullConfig.daynight.map((dn: any, i: number) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-mono">{dn.ext}</td>
                      <td className="py-2 pr-4 text-xs">{dn.dest || '-'}</td>
                      <td className="py-2 pr-4">{dn.description || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Time Conditions */}
      {(fullConfig.time_conditions?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <Clock className="h-4 w-4" /> {t('RoutingConfigSection.timeConditions.title', { count: fullConfig.time_conditions.length })}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2 pr-4">{t('RoutingConfigSection.timeConditions.columns.name')}</th><th className="pb-2 pr-4">{t('RoutingConfigSection.timeConditions.columns.timezone')}</th>
                  <th className="pb-2 pr-4">{t('RoutingConfigSection.timeConditions.columns.trueDest')}</th><th className="pb-2 pr-4">{t('RoutingConfigSection.timeConditions.columns.falseDest')}</th>
                  <th className="pb-2 pr-4">{t('RoutingConfigSection.timeConditions.columns.mode')}</th>
                </tr></thead>
                <tbody>
                  {fullConfig.time_conditions.map((tc: any, i: number) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-medium">{tc.displayname}</td>
                      <td className="py-2 pr-4 text-xs">{tc.timezone || '-'}</td>
                      <td className="py-2 pr-4 font-mono text-xs">{tc.truegoto || '-'}</td>
                      <td className="py-2 pr-4 font-mono text-xs">{tc.falsegoto || '-'}</td>
                      <td className="py-2 pr-4">{tc.mode || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </>
  );
}
