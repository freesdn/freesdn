// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * LogsTab · alerts + event log for the switch detail view.
 *
 * Extracted from SwitchesPage as part of the monolith breakup. Receives both
 * datasets via props; purely presentational.
 */
import { AlertTriangle, Clock } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import type { SwitchEvent } from '@/lib/api';

export interface LogsTabProps {
  switchAlerts: SwitchEvent[] | undefined;
  switchEvents: SwitchEvent[] | undefined;
}

export function LogsTab({ switchAlerts, switchEvents }: LogsTabProps) {
  const { t } = useTranslation('switches');
  return (
    <>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Alerts */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              {t('LogsTab.alerts.title')}
            </CardTitle>
            <CardDescription>{t('LogsTab.alerts.count', { count: switchAlerts?.length || 0 })}</CardDescription>
          </CardHeader>
          <CardContent>
            {switchAlerts?.length ? (
              <div className="space-y-2 max-h-[400px] overflow-y-auto">
                {switchAlerts.map((alert, i) => (
                  <div key={alert.id || i} className="flex items-start gap-3 p-2 rounded-lg border">
                    <div className={`mt-0.5 h-2 w-2 rounded-full flex-shrink-0 ${
                      alert.level === 'critical' ? 'bg-red-500' :
                      alert.level === 'error' ? 'bg-orange-500' :
                      alert.level === 'warning' ? 'bg-yellow-500' : 'bg-blue-500'
                    }`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm">{alert.message || t('LogsTab.alerts.noDescription')}</p>
                      <div className="flex items-center gap-2 mt-1">
                        <Badge variant="outline" className="text-xs">{alert.level || 'info'}</Badge>
                        {alert.timestamp && (
                          <span className="text-xs text-muted-foreground">
                            {new Date(alert.timestamp * 1000).toLocaleString()}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground py-4 text-center">{t('LogsTab.alerts.empty')}</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Event Log */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Clock className="h-4 w-4" />
            {t('LogsTab.events.title')}
          </CardTitle>
          <CardDescription>{t('LogsTab.events.count', { count: switchEvents?.length || 0 })}</CardDescription>
        </CardHeader>
        <CardContent>
          {switchEvents?.length ? (
            <div className="max-h-[500px] overflow-y-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('LogsTab.events.columns.time')}</TableHead>
                    <TableHead>{t('LogsTab.events.columns.level')}</TableHead>
                    <TableHead>{t('LogsTab.events.columns.category')}</TableHead>
                    <TableHead>{t('LogsTab.events.columns.message')}</TableHead>
                    <TableHead>{t('LogsTab.events.columns.device')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {switchEvents.map((event, i) => (
                    <TableRow key={event.id || i}>
                      <TableCell className="text-xs whitespace-nowrap">
                        {event.timestamp ? new Date(event.timestamp * 1000).toLocaleString() : '-'}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={event.level === 'error' || event.level === 'critical' ? 'destructive' : 'secondary'}
                          className="text-xs"
                        >
                          {event.level || 'info'}
                        </Badge>
                      </TableCell>
                      <TableCell className="capitalize text-xs">{event.category || '-'}</TableCell>
                      <TableCell className="text-sm max-w-[400px] truncate">{event.message || '-'}</TableCell>
                      <TableCell className="text-xs">{event.device_name || event.device_mac || '-'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground py-4 text-center">{t('LogsTab.events.empty')}</p>
          )}
        </CardContent>
      </Card>
    </>
  );
}
