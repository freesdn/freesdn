/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import { motion } from 'framer-motion';
import {
  Shield,
  AlertTriangle,
  Clock,
  RefreshCw,
  Eye,
  Download,
  CheckCircle,
  XCircle,
  AlertCircle,
  Info,
  User,
  Globe,
  Key,
  Lock,
  Unlock,
  LogIn,
  LogOut,
  UserPlus,
  Settings,
} from 'lucide-react';
import { PageHeader, PageTabs, type PageTab } from '@/components/layout';
import { Card, CardContent } from '@/components/ui/card';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { SearchBar } from '@/components/ui/search-bar';
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
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { ScrollArea } from '@/components/ui/scroll-area';
import { api, getApiErrorMessage } from '@/lib/api';
import { EmptyState } from '@/components/ui/empty-state';
import { useToast } from '@/hooks/use-toast';
import { formatDistanceToNow, format } from 'date-fns';

interface SecurityEvent {
  id: string;
  timestamp: string;
  event_type: string;
  severity?: string;
  user_id?: string;
  user_email?: string;
  ip_address?: string;
  details?: Record<string, any>;
  risk_score?: number;
  success?: boolean;
}

interface AuditLog {
  id: string;
  timestamp: string;
  actor_type: string;
  actor_id?: string;
  actor_name?: string;
  ip_address?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  resource_name?: string;
  changes?: Record<string, any>;
  status: string;
}

// API functions
const securityApi = {
  getEvents: (params?: any) => api.get('/audit/security-events', { params }),
  getEventById: (id: string) => api.get(`/audit/security-events/${id}`),
};

const auditApi = {
  getLogs: (params?: any) => api.get('/audit/logs', { params }),
  getLogById: (id: string) => api.get(`/audit/logs/${id}`),
};

export default function SecurityPage() {
  const { t } = useTranslation('security');
  const { toast } = useToast();
  const [isExporting, setIsExporting] = useState(false);
  const tabs: PageTab[] = [
    { value: 'events', label: t('SecurityPage.tabs.securityEvents'), content: <SecurityEventsTab /> },
    { value: 'audit',  label: t('SecurityPage.tabs.auditLogs'),      content: <AuditLogsTab /> },
  ];

  // POST /audit/export returns a StreamingResponse (CSV/JSON blob with a
  // Content-Disposition filename). The header Export action is shared across
  // both tabs and the backend export endpoint operates on the AuditLogRecord
  // trail, so we export audit logs as CSV. We pull the filename from the
  // Content-Disposition header when present and fall back to a timestamped
  // default. Truncation (X-Result-Truncated) is surfaced via toast.
  const handleExport = async () => {
    if (isExporting) return;
    setIsExporting(true);
    try {
      const response = await api.post(
        '/audit/export',
        { format: 'csv' },
        { responseType: 'blob' },
      );

      const disposition = response.headers?.['content-disposition'] as string | undefined;
      const match = disposition?.match(/filename="?([^"]+)"?/);
      const filename =
        match?.[1] ||
        `audit_export_${format(new Date(), 'yyyyMMdd_HHmmss')}.csv`;

      const blob = new Blob([response.data], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);

      const truncated = response.headers?.['x-result-truncated'] === 'true';
      if (truncated) {
        toast({
          title: t('SecurityPage.export.truncatedTitle'),
          description: t('SecurityPage.export.truncatedDescription', {
            limit: response.headers?.['x-result-limit'] ?? '',
            total: response.headers?.['x-result-total'] ?? '',
          }),
        });
      } else {
        toast({
          title: t('SecurityPage.export.successTitle'),
          description: t('SecurityPage.export.successDescription'),
        });
      }
    } catch (err) {
      toast({
        title: t('SecurityPage.export.errorTitle'),
        description: getApiErrorMessage(err, t('SecurityPage.export.errorDescription')),
        variant: 'destructive',
      });
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="space-y-6">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <PageHeader
            title={t('SecurityPage.title')}
            description={t('SecurityPage.description')}
            icon={Shield}
            secondaryActions={[
              {
                label: t('SecurityPage.actions.export'),
                icon: Download,
                onClick: handleExport,
                loading: isExporting,
                disabled: isExporting,
              }
            ]}
          />
        </motion.div>

        <PageTabs basePath="/security" tabs={tabs} />
      </div>
  );
}

// Security Events Tab
function SecurityEventsTab() {
  const { t } = useTranslation('security');
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  // NOTE: SecurityEventRecord has no site_id column, so the backend cannot
  // site-filter these events. We intentionally do NOT send `site_id` here (and
  // omit selectedSiteId from the queryKey) so the global site filter doesn't
  // imply filtering that can't happen or trigger misleading refetches. The
  // Audit Logs tab DOES site-filter (AuditLogRecord has site_id).
  const {
    data: eventsData,
    isLoading,
    isError,
    refetch,
  } = useQuery({
    queryKey: ['security-events', search, severityFilter],
    queryFn: async () => {
      const params: any = { per_page: 50 };
      if (search) params.search = search;
      if (severityFilter !== 'all') params.severity = severityFilter;
      const response = await securityApi.getEvents(params);
      return response.data;
    },
  });

  const events: SecurityEvent[] = eventsData?.items || [];

  // Backend (/audit/security-events) does not send a `severity` field, it
  // sends `risk_score`. Derive a display severity from risk_score so badges
  // and stats remain meaningful without faking a backend column.
  const deriveSeverity = (event: SecurityEvent): string => {
    if (event.severity) return event.severity;
    const score = event.risk_score ?? 0;
    if (score >= 80) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 20) return 'medium';
    return 'low';
  };

  const getSeverityColor = (severity?: string) => {
    switch ((severity ?? 'info').toLowerCase()) {
      case 'critical':
        return 'bg-red-500/10 text-red-600 border-red-500/20';
      case 'high':
        return 'bg-orange-500/10 text-orange-600 border-orange-500/20';
      case 'medium':
        return 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20';
      case 'low':
        return 'bg-primary/10 text-primary border-primary/20';
      default:
        return 'bg-muted text-muted-foreground border-border';
    }
  };

  const getSeverityIcon = (severity?: string) => {
    switch ((severity ?? 'info').toLowerCase()) {
      case 'critical':
        return <XCircle className="h-4 w-4" />;
      case 'high':
        return <AlertTriangle className="h-4 w-4" />;
      case 'medium':
        return <AlertCircle className="h-4 w-4" />;
      case 'low':
        return <Info className="h-4 w-4" />;
      default:
        return <Info className="h-4 w-4" />;
    }
  };

  const getEventIcon = (eventType: string) => {
    switch (eventType) {
      case 'login_success':
        return <LogIn className="h-4 w-4 text-green-500" />;
      case 'login_failed':
        return <LogIn className="h-4 w-4 text-red-500" />;
      case 'logout':
        return <LogOut className="h-4 w-4 text-blue-500" />;
      case 'password_change':
        return <Key className="h-4 w-4 text-yellow-500" />;
      case 'mfa_enabled':
      case 'mfa_disabled':
        return <Shield className="h-4 w-4 text-purple-500" />;
      case 'account_locked':
        return <Lock className="h-4 w-4 text-red-500" />;
      case 'account_unlocked':
        return <Unlock className="h-4 w-4 text-green-500" />;
      case 'user_created':
        return <UserPlus className="h-4 w-4 text-blue-500" />;
      case 'permission_change':
        return <Settings className="h-4 w-4 text-orange-500" />;
      default:
        return <AlertCircle className="h-4 w-4 text-muted-foreground" />;
    }
  };

  // Stats, backend sends no `severity`/`reviewed`; derive from risk_score and
  // use the real `success` flag for the "needs attention" count.
  const stats = {
    total: events.length,
    critical: events.filter((e) => deriveSeverity(e) === 'critical').length,
    high: events.filter((e) => deriveSeverity(e) === 'high').length,
    unreviewed: events.filter((e) => e.success === false).length,
  };

  return (
    <div className="space-y-6">
      {isError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('SecurityPage.errors.partialLoad')}</span>
          </CardContent>
        </Card>
      )}

      {/* Stats */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <StatsGrid
          columns={4}
          stats={[
            { title: t('SecurityPage.stats.totalEvents'), value: stats.total, icon: Shield, variant: 'primary' },
            { title: t('SecurityPage.stats.critical'), value: stats.critical, icon: XCircle, variant: 'destructive' },
            { title: t('SecurityPage.stats.highSeverity'), value: stats.high, icon: AlertTriangle, variant: 'warning' },
            { title: t('SecurityPage.stats.unreviewed'), value: stats.unreviewed, icon: Eye, variant: 'info' },
          ]}
        />
      </motion.div>

      {/* Filters */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="flex flex-col sm:flex-row gap-4"
      >
        <div className="relative flex-1">
          <SearchBar
            value={search}
            onChange={setSearch}
            placeholder={t('SecurityPage.events.searchPlaceholder')}
          />
        </div>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder={t('SecurityPage.events.severityPlaceholder')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('SecurityPage.severity.all')}</SelectItem>
            <SelectItem value="critical">{t('SecurityPage.severity.critical')}</SelectItem>
            <SelectItem value="high">{t('SecurityPage.severity.high')}</SelectItem>
            <SelectItem value="medium">{t('SecurityPage.severity.medium')}</SelectItem>
            <SelectItem value="low">{t('SecurityPage.severity.low')}</SelectItem>
          </SelectContent>
        </Select>
        <Button variant="outline" size="icon" onClick={() => refetch()}>
          <RefreshCw className="h-4 w-4" />
        </Button>
      </motion.div>

      {/* Events List */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        {isLoading ? (
          <Card>
            <CardContent noOffset className="space-y-4 p-6">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="flex items-center gap-4">
                  <Skeleton className="h-10 w-10 rounded-lg" />
                  <div className="space-y-2 flex-1">
                    <Skeleton className="h-4 w-[300px]" />
                    <Skeleton className="h-3 w-[200px]" />
                  </div>
                  <Skeleton className="h-6 w-20" />
                </div>
              ))}
            </CardContent>
          </Card>
        ) : events.length === 0 ? (
          <EmptyState
            icon={Shield}
            title={t('SecurityPage.events.emptyTitle')}
            description={t('SecurityPage.events.emptyDescription')}
            variant="card"
          />
        ) : (
          <Card>
            <CardContent className="p-0">
              <ScrollArea className="h-[500px]">
                <div className="divide-y">
                  {events.map((event) => (
                    <div
                      key={event.id}
                      className="p-4 hover:bg-muted/30 cursor-pointer transition-colors"
                      onClick={() => setSelectedEvent(event)}
                    >
                      <div className="flex items-start gap-4">
                        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted">
                          {getEventIcon(event.event_type)}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-medium">
                              {event.event_type.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
                            </span>
                            <Badge className={getSeverityColor(deriveSeverity(event))}>
                              {getSeverityIcon(deriveSeverity(event))}
                              <span className="ml-1">{deriveSeverity(event)}</span>
                            </Badge>
                            {event.success === false && (
                              <Badge variant="outline" className="text-yellow-600 border-yellow-500/20">
                                {t('SecurityPage.events.unreviewed')}
                              </Badge>
                            )}
                          </div>
                          <p className="text-sm text-muted-foreground mt-1">
                            {t('SecurityPage.events.eventFrom', { source: event.user_email || event.ip_address || t('SecurityPage.events.unknownSource') })}
                          </p>
                          <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                            {event.user_email && (
                              <span className="flex items-center gap-1">
                                <User className="h-3 w-3" />
                                {event.user_email}
                              </span>
                            )}
                            {event.ip_address && (
                              <span className="flex items-center gap-1">
                                <Globe className="h-3 w-3" />
                                {event.ip_address}
                              </span>
                            )}
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })}
                            </span>
                          </div>
                        </div>
                        {event.risk_score && (
                          <div className="text-right">
                            <span className="text-sm font-medium">{t('SecurityPage.fields.riskScore')}</span>
                            <p className={`text-lg font-bold ${
                              event.risk_score >= 80 ? 'text-red-500' :
                              event.risk_score >= 50 ? 'text-orange-500' :
                              'text-green-500'
                            }`}>
                              {event.risk_score}
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        )}
      </motion.div>

      {/* Event Detail Dialog */}
      <Dialog open={!!selectedEvent} onOpenChange={(open) => !open && setSelectedEvent(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {selectedEvent && getEventIcon(selectedEvent.event_type)}
              {selectedEvent?.event_type.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
            </DialogTitle>
            <DialogDescription>
              {selectedEvent?.timestamp && format(new Date(selectedEvent.timestamp), 'PPpp')}
            </DialogDescription>
          </DialogHeader>
          {selectedEvent && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm font-medium">{t('SecurityPage.fields.severity')}</p>
                  <Badge className={getSeverityColor(deriveSeverity(selectedEvent))}>
                    {deriveSeverity(selectedEvent)}
                  </Badge>
                </div>
                <div>
                  <p className="text-sm font-medium">{t('SecurityPage.fields.status')}</p>
                  <Badge variant={selectedEvent.success === false ? 'outline' : 'default'}>
                    {selectedEvent.success === false ? t('SecurityPage.events.pendingReview') : t('SecurityPage.events.reviewed')}
                  </Badge>
                </div>
                {selectedEvent.user_email && (
                  <div>
                    <p className="text-sm font-medium">{t('SecurityPage.fields.user')}</p>
                    <p className="text-sm text-muted-foreground">{selectedEvent.user_email}</p>
                  </div>
                )}
                {selectedEvent.ip_address && (
                  <div>
                    <p className="text-sm font-medium">{t('SecurityPage.fields.ipAddress')}</p>
                    <p className="text-sm text-muted-foreground">{selectedEvent.ip_address}</p>
                  </div>
                )}
                {selectedEvent.risk_score != null && (
                  <div>
                    <p className="text-sm font-medium">{t('SecurityPage.fields.riskScore')}</p>
                    <p className={`text-lg font-bold ${
                      selectedEvent.risk_score >= 80 ? 'text-red-500' :
                      selectedEvent.risk_score >= 50 ? 'text-orange-500' :
                      'text-green-500'
                    }`}>
                      {selectedEvent.risk_score}/100
                    </p>
                  </div>
                )}
              </div>
              {Object.keys(selectedEvent.details ?? {}).length > 0 && (
                <div>
                  <p className="text-sm font-medium mb-2">{t('SecurityPage.fields.additionalDetails')}</p>
                  <pre className="text-xs bg-muted p-3 rounded-lg overflow-auto max-h-40">
                    {JSON.stringify(selectedEvent.details, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

// Audit Logs Tab
function AuditLogsTab() {
  const { t } = useTranslation('security');
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState<string>('all');
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  const {
    data: logsData,
    isLoading,
    isError,
    refetch,
  } = useQuery({
    queryKey: ['audit-logs', search, actionFilter, { siteId: selectedSiteId }],
    queryFn: async () => {
      const params: any = { per_page: 50 };
      if (search) params.search = search;
      if (actionFilter !== 'all') params.action = actionFilter;
      if (selectedSiteId) params.site_id = selectedSiteId;
      const response = await auditApi.getLogs(params);
      return response.data;
    },
  });

  const logs: AuditLog[] = logsData?.items || [];

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'success':
        return 'bg-green-500/10 text-green-600 border-green-500/20';
      case 'failure':
      case 'failed':
        return 'bg-destructive/10 text-destructive border-destructive/20';
      default:
        return 'bg-muted text-muted-foreground border-border';
    }
  };

  const getActionIcon = (action: string) => {
    if (action.includes('create')) return <UserPlus className="h-4 w-4 text-green-500" />;
    if (action.includes('update')) return <Settings className="h-4 w-4 text-blue-500" />;
    if (action.includes('delete')) return <XCircle className="h-4 w-4 text-red-500" />;
    if (action.includes('login')) return <LogIn className="h-4 w-4 text-purple-500" />;
    if (action.includes('logout')) return <LogOut className="h-4 w-4 text-orange-500" />;
    return <Clock className="h-4 w-4 text-muted-foreground" />;
  };

  return (
    <div className="space-y-6">
      {/* Filters */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col sm:flex-row gap-4"
      >
        <div className="relative flex-1">
          <SearchBar
            value={search}
            onChange={setSearch}
            placeholder={t('SecurityPage.audit.searchPlaceholder')}
          />
        </div>
        <Select value={actionFilter} onValueChange={setActionFilter}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder={t('SecurityPage.audit.actionPlaceholder')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('SecurityPage.actionFilter.all')}</SelectItem>
            <SelectItem value="create">{t('SecurityPage.actionFilter.create')}</SelectItem>
            <SelectItem value="update">{t('SecurityPage.actionFilter.update')}</SelectItem>
            <SelectItem value="delete">{t('SecurityPage.actionFilter.delete')}</SelectItem>
            <SelectItem value="login">{t('SecurityPage.actionFilter.login')}</SelectItem>
            <SelectItem value="logout">{t('SecurityPage.actionFilter.logout')}</SelectItem>
          </SelectContent>
        </Select>
        <Button variant="outline" size="icon" onClick={() => refetch()}>
          <RefreshCw className="h-4 w-4" />
        </Button>
      </motion.div>

      {isError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('SecurityPage.errors.partialLoad')}</span>
          </CardContent>
        </Card>
      )}

      {/* Logs List */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Card>
          <CardContent className="p-0">
            {isLoading ? (
              <div className="space-y-4 p-6">
                {Array.from({ length: 5 }).map((_, i) => (
                  <div key={i} className="flex items-center gap-4">
                    <Skeleton className="h-10 w-10 rounded-lg" />
                    <div className="space-y-2 flex-1">
                      <Skeleton className="h-4 w-[300px]" />
                      <Skeleton className="h-3 w-[200px]" />
                    </div>
                    <Skeleton className="h-6 w-20" />
                  </div>
                ))}
              </div>
            ) : logs.length === 0 ? (
              <EmptyState
                icon={Clock}
                title={t('SecurityPage.audit.emptyTitle')}
                description={t('SecurityPage.audit.emptyDescription')}
                variant="card"
              />
            ) : (
              <ScrollArea className="h-[500px]">
                <div className="divide-y">
                  {logs.map((log) => (
                    <div
                      key={log.id}
                      className="p-4 hover:bg-muted/30 cursor-pointer transition-colors"
                      onClick={() => setSelectedLog(log)}
                    >
                      <div className="flex items-start gap-4">
                        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted">
                          {getActionIcon(log.action)}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-medium">
                              {log.action.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
                            </span>
                            <Badge variant="outline">{log.resource_type}</Badge>
                            <Badge className={getStatusColor(log.status)}>
                              {log.status === 'success' ? (
                                <CheckCircle className="h-3 w-3 mr-1" />
                              ) : (
                                <XCircle className="h-3 w-3 mr-1" />
                              )}
                              {log.status}
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground mt-1">
                            {log.resource_name || log.resource_id || t('SecurityPage.common.notAvailable')}
                          </p>
                          <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                            {log.actor_name && (
                              <span className="flex items-center gap-1">
                                <User className="h-3 w-3" />
                                {log.actor_name}
                              </span>
                            )}
                            {log.ip_address && (
                              <span className="flex items-center gap-1">
                                <Globe className="h-3 w-3" />
                                {log.ip_address}
                              </span>
                            )}
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {formatDistanceToNow(new Date(log.timestamp), { addSuffix: true })}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      </motion.div>

      {/* Log Detail Dialog */}
      <Dialog open={!!selectedLog} onOpenChange={(open) => !open && setSelectedLog(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {selectedLog && getActionIcon(selectedLog.action)}
              {selectedLog?.action.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
            </DialogTitle>
            <DialogDescription>
              {selectedLog?.timestamp && format(new Date(selectedLog.timestamp), 'PPpp')}
            </DialogDescription>
          </DialogHeader>
          {selectedLog && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm font-medium">{t('SecurityPage.fields.status')}</p>
                  <Badge className={getStatusColor(selectedLog.status)}>
                    {selectedLog.status}
                  </Badge>
                </div>
                <div>
                  <p className="text-sm font-medium">{t('SecurityPage.fields.resourceType')}</p>
                  <Badge variant="outline">{selectedLog.resource_type}</Badge>
                </div>
                {selectedLog.actor_name && (
                  <div>
                    <p className="text-sm font-medium">{t('SecurityPage.fields.actor')}</p>
                    <p className="text-sm text-muted-foreground">{selectedLog.actor_name}</p>
                  </div>
                )}
                {selectedLog.ip_address && (
                  <div>
                    <p className="text-sm font-medium">{t('SecurityPage.fields.ipAddress')}</p>
                    <p className="text-sm text-muted-foreground">{selectedLog.ip_address}</p>
                  </div>
                )}
                {selectedLog.resource_name && (
                  <div>
                    <p className="text-sm font-medium">{t('SecurityPage.fields.resource')}</p>
                    <p className="text-sm text-muted-foreground">{selectedLog.resource_name}</p>
                  </div>
                )}
              </div>
              {Object.keys(selectedLog.changes ?? {}).length > 0 && (
                <div>
                  <p className="text-sm font-medium mb-2">{t('SecurityPage.fields.changes')}</p>
                  <pre className="text-xs bg-muted p-3 rounded-lg overflow-auto max-h-60">
                    {JSON.stringify(selectedLog.changes, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
