// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Security Audit Page
 * 
 * View security events, anomalies, and compliance reports.
 */
import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation } from '@tanstack/react-query';
import { PageHeader } from '@/components/layout';
import { securityAuditApi, SecurityEvent } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
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
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Shield, Download, AlertTriangle, ShieldCheck } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

// Severity badge colors
const severityColors: Record<string, string> = {
  low: 'bg-muted text-muted-foreground',
  medium: 'bg-warning/20 text-warning',
  high: 'bg-orange-500/20 text-orange-500',
  critical: 'bg-destructive/20 text-destructive',
};

// Outcome badge colors
const outcomeColors: Record<string, string> = {
  success: 'bg-success/20 text-success',
  failure: 'bg-destructive/20 text-destructive',
  blocked: 'bg-warning/20 text-warning',
};

interface EventRowProps {
  event: SecurityEvent;
  onClick: (event: SecurityEvent) => void;
}

const EventRow: React.FC<EventRowProps> = ({ event, onClick }) => {
  return (
    <tr className="hover:bg-muted/50 cursor-pointer" onClick={() => onClick(event)}>
      <td className="px-6 py-4 whitespace-nowrap">
        <span className="text-sm font-medium text-foreground">{event.event_type}</span>
      </td>
      <td className="px-6 py-4 whitespace-nowrap">
        <span className={`px-2 py-1 text-xs font-medium rounded ${severityColors[event.severity] || 'bg-muted text-muted-foreground'}`}>
          {event.severity}
        </span>
      </td>
      <td className="px-6 py-4 whitespace-nowrap">
        <span className={`px-2 py-1 text-xs font-medium rounded ${outcomeColors[event.outcome] || 'bg-muted text-muted-foreground'}`}>
          {event.outcome}
        </span>
      </td>
      <td className="px-6 py-4 whitespace-nowrap text-sm text-muted-foreground">
        {event.source_ip || '-'}
      </td>
      <td className="px-6 py-4 whitespace-nowrap text-sm text-muted-foreground">
        {event.action || '-'}
      </td>
      <td className="px-6 py-4 whitespace-nowrap text-sm text-muted-foreground">
        {new Date(event.timestamp).toLocaleString()}
      </td>
    </tr>
  );
};

interface SecuritySummaryProps {
  summary: {
    total_events: number;
    failed_logins: number;
    suspicious_activities: number;
    events_by_severity: Record<string, number>;
  };
}

const SecuritySummary: React.FC<SecuritySummaryProps> = ({ summary }) => {
  const { t } = useTranslation('security');
  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
      <Card>
        <CardContent noOffset className="p-6">
          <p className="text-sm font-medium text-muted-foreground">{t('SecurityAuditPage.summary.totalEvents')}</p>
          <p className="text-3xl font-bold text-foreground mt-1">{summary.total_events.toLocaleString()}</p>
        </CardContent>
      </Card>
      <Card>
        <CardContent noOffset className="p-6">
          <p className="text-sm font-medium text-muted-foreground">{t('SecurityAuditPage.summary.failedLogins')}</p>
          <p className="text-3xl font-bold text-destructive mt-1">{summary.failed_logins}</p>
        </CardContent>
      </Card>
      <Card>
        <CardContent noOffset className="p-6">
          <p className="text-sm font-medium text-muted-foreground">{t('SecurityAuditPage.summary.suspiciousActivity')}</p>
          <p className="text-3xl font-bold text-orange-500 mt-1">{summary.suspicious_activities}</p>
        </CardContent>
      </Card>
      <Card>
        <CardContent noOffset className="p-6">
          <p className="text-sm font-medium text-muted-foreground">{t('SecurityAuditPage.summary.criticalEvents')}</p>
          <p className="text-3xl font-bold text-destructive mt-1">{summary.events_by_severity?.critical || 0}</p>
        </CardContent>
      </Card>
    </div>
  );
};

interface EventDetailModalProps {
  event: SecurityEvent | null;
  onClose: () => void;
}

const EventDetailModal: React.FC<EventDetailModalProps> = ({ event, onClose }) => {
  const { t } = useTranslation('security');
  return (
    <Dialog open={!!event} onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-auto">
        <DialogHeader>
          <DialogTitle>{t('SecurityAuditPage.detail.title')}</DialogTitle>
        </DialogHeader>
        {event && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-muted-foreground">{t('SecurityAuditPage.fields.eventType')}</p>
                <p className="font-medium">{event.event_type}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">{t('SecurityAuditPage.fields.severity')}</p>
                <span className={`px-2 py-1 text-xs font-medium rounded ${severityColors[event.severity]}`}>
                  {event.severity}
                </span>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">{t('SecurityAuditPage.fields.outcome')}</p>
                <span className={`px-2 py-1 text-xs font-medium rounded ${outcomeColors[event.outcome]}`}>
                  {event.outcome}
                </span>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">{t('SecurityAuditPage.fields.timestamp')}</p>
                <p className="font-medium">{new Date(event.timestamp).toLocaleString()}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">{t('SecurityAuditPage.fields.sourceIp')}</p>
                <p className="font-medium">{event.source_ip || '-'}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">{t('SecurityAuditPage.fields.action')}</p>
                <p className="font-medium">{event.action || '-'}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">{t('SecurityAuditPage.fields.resourceType')}</p>
                <p className="font-medium">{event.resource_type || '-'}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">{t('SecurityAuditPage.fields.userId')}</p>
                <p className="font-medium font-mono text-sm">{event.user_id || '-'}</p>
              </div>
            </div>

            {event.details && Object.keys(event.details).length > 0 && (
              <div>
                <p className="text-sm text-muted-foreground mb-2">{t('SecurityAuditPage.detail.details')}</p>
                <pre className="bg-muted rounded-lg p-4 text-sm overflow-auto">
                  {JSON.stringify(event.details, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
};

interface AnomalyAlertProps {
  anomalies: Array<{
    anomaly_type: string;
    description: string;
    severity: string;
    detected_at: string;
  }>;
}

const AnomalyAlerts: React.FC<AnomalyAlertProps> = ({ anomalies }) => {
  const { t } = useTranslation('security');
  if (anomalies.length === 0) return null;

  return (
    <div className="bg-destructive/10 border border-destructive/20 rounded-xl p-6">
      <div className="flex items-center space-x-2 mb-4">
        <AlertTriangle className="h-6 w-6 text-destructive" />
        <h3 className="text-lg font-semibold text-destructive">{t('SecurityAuditPage.anomalies.heading')}</h3>
      </div>
      <div className="space-y-3">
        {anomalies.map((anomaly, index) => (
          <Card key={index}>
            <CardContent noOffset className="p-4">
              <div className="flex items-start justify-between">
                <div>
                  <p className="font-medium text-foreground">{anomaly.anomaly_type}</p>
                  <p className="text-sm text-muted-foreground">{anomaly.description}</p>
                </div>
                <span className={`px-2 py-1 text-xs font-medium rounded ${severityColors[anomaly.severity]}`}>
                  {anomaly.severity}
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                {t('SecurityAuditPage.anomalies.detected', { time: new Date(anomaly.detected_at).toLocaleString() })}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

export default function SecurityAuditPage() {
  const { t } = useTranslation('security');
  const { toast } = useToast();
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  const [filters, setFilters] = useState({
    event_type: '',
    severity: '',
    period: '24h',
    page: 1,
  });

  // Query for events
  const { 
    data: eventsData, 
    isLoading: eventsLoading, 
    error: eventsError,
    isFetching: eventsFetching,
    refetch: refetchEvents,
  } = useQuery({
    // No siteId in the key: /security/events has no site dimension, so
    // re-keying on it only refetched the same rows on every site switch.
    queryKey: ['security-events', filters],
    queryFn: async () => {
      const res = await securityAuditApi.listEvents({
        event_type: filters.event_type || undefined,
        severity: filters.severity || undefined,
        page: filters.page,
        page_size: 20,
      });
      return res.data;
    },
  });

  // Query for summary
  const {
    data: summary,
    isLoading: summaryLoading,
    isError: summaryError,
    refetch: refetchSummary,
  } = useQuery({
    queryKey: ['security-summary', filters.period],
    queryFn: async () => {
      const res = await securityAuditApi.getSummary({ period: filters.period });
      return res.data;
    },
    placeholderData: {
      total_events: 0,
      failed_logins: 0,
      suspicious_activities: 0,
      events_by_severity: { low: 0, medium: 0, high: 0, critical: 0 },
    },
  });

  // Query for anomalies
  const {
    data: anomalies = [],
    isError: anomaliesError,
    refetch: refetchAnomalies,
  } = useQuery({
    queryKey: ['security-anomalies', filters.period],
    queryFn: async () => {
      const res = await securityAuditApi.getAnomalies({ period: filters.period });
      return res.data || [];
    },
  });

  // Export mutation
  const exportMutation = useMutation({
    mutationFn: async () => {
      const end = new Date().toISOString();
      const start = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      return securityAuditApi.exportLog(start, end, 'csv');
    },
    onSuccess: () => {
      toast({ title: t('SecurityAuditPage.toast.successTitle'), description: t('SecurityAuditPage.toast.exportStarted') });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      toast({ title: t('SecurityAuditPage.toast.errorTitle'), description: t('SecurityAuditPage.toast.exportFailed', { error: err.response?.data?.detail || err.message }), variant: "destructive" });
    },
  });

  const events = eventsData?.items || [];
  const total = eventsData?.total || 0;
  const isLoading = eventsLoading || summaryLoading;
  const isFetching = eventsFetching;

  const handleRefresh = () => {
    refetchEvents();
    refetchSummary();
    refetchAnomalies();
  };

  if (isLoading && events.length === 0) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-10 w-1/3" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <Skeleton className="h-24 w-full rounded-xl" />
          <Skeleton className="h-24 w-full rounded-xl" />
          <Skeleton className="h-24 w-full rounded-xl" />
          <Skeleton className="h-24 w-full rounded-xl" />
        </div>
        <Skeleton className="h-12 w-full rounded-xl" />
        <Skeleton className="h-64 w-full rounded-xl" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        title={t('SecurityAuditPage.header.title')}
        description={t('SecurityAuditPage.header.description')}
        icon={Shield}
        onRefresh={handleRefresh}
        refreshing={isFetching}
        secondaryActions={[
          {
            label: t('SecurityAuditPage.actions.exportLog'),
            icon: Download,
            onClick: () => exportMutation.mutate(),
            disabled: exportMutation.isPending,
          },
        ]}
      />

      {/* Error Alert */}
      {(eventsError || summaryError || anomaliesError) && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">
              {eventsError
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                ? (eventsError as any).response?.data?.detail || t('SecurityAuditPage.errors.loadEvents')
                : t('SecurityAuditPage.errors.partialLoad')}
            </span>
          </CardContent>
        </Card>
      )}

      {/* Anomaly Alerts */}
      <AnomalyAlerts anomalies={anomalies} />

      {/* Summary */}
      {summary && <SecuritySummary summary={summary} />}

      {/* Filters */}
      <Card>
        <CardContent noOffset className="p-4">
          <div className="flex flex-wrap items-center gap-4">
            <Select
              value={filters.event_type || '_all'}
              onValueChange={(v) => setFilters({ ...filters, event_type: v === '_all' ? '' : v, page: 1 })}
            >
              <SelectTrigger className="w-full sm:w-[180px]">
                <SelectValue placeholder={t('SecurityAuditPage.filters.allEventTypes')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="_all">{t('SecurityAuditPage.filters.allEventTypes')}</SelectItem>
                <SelectItem value="login_success">{t('SecurityAuditPage.eventTypes.loginSuccess')}</SelectItem>
                <SelectItem value="login_failure">{t('SecurityAuditPage.eventTypes.loginFailure')}</SelectItem>
                <SelectItem value="permission_denied">{t('SecurityAuditPage.eventTypes.permissionDenied')}</SelectItem>
                <SelectItem value="api_access">{t('SecurityAuditPage.eventTypes.apiAccess')}</SelectItem>
                <SelectItem value="data_export">{t('SecurityAuditPage.eventTypes.dataExport')}</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={filters.severity || '_all'}
              onValueChange={(v) => setFilters({ ...filters, severity: v === '_all' ? '' : v, page: 1 })}
            >
              <SelectTrigger className="w-full sm:w-[160px]">
                <SelectValue placeholder={t('SecurityAuditPage.filters.allSeverities')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="_all">{t('SecurityAuditPage.filters.allSeverities')}</SelectItem>
                <SelectItem value="low">{t('SecurityAuditPage.severity.low')}</SelectItem>
                <SelectItem value="medium">{t('SecurityAuditPage.severity.medium')}</SelectItem>
                <SelectItem value="high">{t('SecurityAuditPage.severity.high')}</SelectItem>
                <SelectItem value="critical">{t('SecurityAuditPage.severity.critical')}</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={filters.period}
              onValueChange={(v) => setFilters({ ...filters, period: v, page: 1 })}
            >
              <SelectTrigger className="w-full sm:w-[160px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="1h">{t('SecurityAuditPage.period.lastHour')}</SelectItem>
                <SelectItem value="6h">{t('SecurityAuditPage.period.last6Hours')}</SelectItem>
                <SelectItem value="24h">{t('SecurityAuditPage.period.last24Hours')}</SelectItem>
                <SelectItem value="7d">{t('SecurityAuditPage.period.last7Days')}</SelectItem>
                <SelectItem value="30d">{t('SecurityAuditPage.period.last30Days')}</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Events Table */}
      <Card className="overflow-hidden">
        <CardContent className="p-0">
          {events.length === 0 ? (
            <div className="flex flex-col items-center justify-center p-12 text-center">
              <ShieldCheck className="h-16 w-16 text-muted-foreground/50 mb-4" />
              <p className="text-muted-foreground">{t('SecurityAuditPage.empty.noEvents')}</p>
            </div>
          ) : (
            <>
              <table className="min-w-full divide-y divide-border">
                <thead className="bg-muted">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      {t('SecurityAuditPage.table.eventType')}
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      {t('SecurityAuditPage.table.severity')}
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      {t('SecurityAuditPage.table.outcome')}
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      {t('SecurityAuditPage.table.sourceIp')}
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      {t('SecurityAuditPage.table.action')}
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      {t('SecurityAuditPage.table.time')}
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {events.map((event) => (
                    <EventRow key={event.id} event={event} onClick={setSelectedEvent} />
                  ))}
                </tbody>
              </table>
              
              {/* Pagination */}
              <div className="px-6 py-4 border-t border-border flex items-center justify-between">
                <p className="text-sm text-muted-foreground">
                  {t('SecurityAuditPage.pagination.showing', {
                    from: (filters.page - 1) * 20 + 1,
                    to: Math.min(filters.page * 20, total),
                    total,
                  })}
                </p>
                <div className="flex space-x-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setFilters({ ...filters, page: filters.page - 1 })}
                    disabled={filters.page === 1}
                  >
                    {t('SecurityAuditPage.pagination.previous')}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setFilters({ ...filters, page: filters.page + 1 })}
                    disabled={filters.page * 20 >= total}
                  >
                    {t('SecurityAuditPage.pagination.next')}
                  </Button>
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Event Detail Modal */}
      <EventDetailModal event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      </div>
  );
}
