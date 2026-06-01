// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Log Explorer Page
 *
 * Full-featured log search with time range picker, filter bar,
 * expandable row detail, and CSV export.
 */

import { useState, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import {
  Search,
  Filter,
  Download,
  ChevronDown,
  ChevronRight,
  FileText,
  ScrollText,
  Loader2,
  AlertTriangle,
} from 'lucide-react';

import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { EmptyState } from '@/components/ui/empty-state';
import { Skeleton } from '@/components/ui/skeleton';
import { PageHeader } from '@/components/layout';


// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface LogEntry {
  id: string;
  source_type: string;
  source_ip: string;
  device_id: string | null;
  severity: string | null;
  facility: string | null;
  hostname: string | null;
  app_name: string | null;
  message: string;
  enterprise_oid: string | null;
  trap_type: string | null;
  varbinds: Record<string, string> | null;
  timestamp: string;
}

interface LogSearchResult {
  logs: LogEntry[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

interface Filters {
  source_type: string;
  severity: string;
  q: string;
  start_time: string;
  end_time: string;
}


// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  emergency: 'bg-red-600 text-white',
  alert: 'bg-red-500 text-white',
  critical: 'bg-red-400 text-white',
  error: 'bg-orange-500 text-white',
  warning: 'bg-yellow-500 text-black',
  notice: 'bg-blue-500 text-white',
  info: 'bg-blue-400 text-white',
  debug: 'bg-gray-400 text-white',
};

function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return <Badge variant="outline">-</Badge>;
  const cls = SEVERITY_COLORS[severity.toLowerCase()] ?? 'bg-gray-300 text-black';
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ${cls}`}>
      {severity}
    </span>
  );
}

// ISO string for datetime-local inputs
function toInputDatetime(iso: string): string {
  return iso.slice(0, 16);
}

function fromInputDatetime(local: string): string {
  return local ? new Date(local).toISOString() : '';
}

// Time range presets. Labels are translated at the render site via labelKey.
const PRESETS = [
  { labelKey: 'last15min', minutes: 15 },
  { labelKey: 'last1hour', minutes: 60 },
  { labelKey: 'last6hours', minutes: 360 },
  { labelKey: 'last24hours', minutes: 1440 },
  { labelKey: 'last7days', minutes: 10080 },
];

function buildPresetRange(minutes: number): { start: string; end: string } {
  const end = new Date();
  const start = new Date(end.getTime() - minutes * 60_000);
  return { start: start.toISOString(), end: end.toISOString() };
}


// ─────────────────────────────────────────────────────────────────────────────
// Detail row
// ─────────────────────────────────────────────────────────────────────────────

function LogDetailRow({ log }: { log: LogEntry }) {
  const { t } = useTranslation('collector');
  return (
    <TableRow className="bg-muted/20">
      <TableCell colSpan={6} className="py-3">
        <div className="grid gap-3 text-sm md:grid-cols-2">
          <div className="space-y-1.5">
            <p><span className="font-medium">{t('LogExplorerPage.detail.sourceIp')}</span> <span className="font-mono">{log.source_ip}</span></p>
            {log.device_id && (
              <p><span className="font-medium">{t('LogExplorerPage.detail.deviceId')}</span> <span className="font-mono text-xs">{log.device_id}</span></p>
            )}
            {log.hostname && (
              <p><span className="font-medium">{t('LogExplorerPage.detail.hostname')}</span> {log.hostname}</p>
            )}
            {log.app_name && (
              <p><span className="font-medium">{t('LogExplorerPage.detail.app')}</span> {log.app_name}</p>
            )}
            {log.facility && (
              <p><span className="font-medium">{t('LogExplorerPage.detail.facility')}</span> {log.facility}</p>
            )}
          </div>
          {log.source_type === 'snmp_trap' ? (
            <div className="space-y-1.5">
              {log.enterprise_oid && (
                <p><span className="font-medium">{t('LogExplorerPage.detail.enterpriseOid')}</span> <span className="font-mono text-xs">{log.enterprise_oid}</span></p>
              )}
              {log.trap_type && (
                <p><span className="font-medium">{t('LogExplorerPage.detail.trapType')}</span> {log.trap_type}</p>
              )}
              {log.varbinds && Object.keys(log.varbinds).length > 0 && (
                <div>
                  <p className="font-medium mb-1">{t('LogExplorerPage.detail.varbinds')}</p>
                  <div className="rounded border bg-background p-2 font-mono text-xs space-y-0.5">
                    {Object.entries(log.varbinds).map(([oid, val]) => (
                      <div key={oid} className="flex gap-2">
                        <span className="text-muted-foreground min-w-0 truncate">{oid}</span>
                        <span>=</span>
                        <span className="truncate">{val}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div>
              <p className="font-medium mb-1">{t('LogExplorerPage.detail.fullMessage')}</p>
              <div className="rounded border bg-background p-2 font-mono text-xs whitespace-pre-wrap break-all">
                {log.message}
              </div>
            </div>
          )}
        </div>
      </TableCell>
    </TableRow>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────

export default function LogExplorerPage() {
  const { t } = useTranslation('collector');
  const [filters, setFilters] = useState<Filters>({
    source_type: '',
    severity: '',
    q: '',
    ...buildPresetRange(60), // default: last 1 hour
    start_time: buildPresetRange(60).start,
    end_time: buildPresetRange(60).end,
  });
  const [page, setPage] = useState(1);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [pendingQ, setPendingQ] = useState('');

  const { data, isLoading, isError, isFetching } = useQuery<LogSearchResult>({
    queryKey: ['collector-logs', filters, page],
    queryFn: () =>
      api
        .get('/collector/logs', {
          params: {
            source_type: filters.source_type || undefined,
            severity: filters.severity || undefined,
            q: filters.q || undefined,
            start_time: filters.start_time || undefined,
            end_time: filters.end_time || undefined,
            page,
            size: 50,
          },
        })
        .then((r) => r.data),
  });

  const applyPreset = useCallback((minutes: number) => {
    const { start, end } = buildPresetRange(minutes);
    setFilters((f) => ({ ...f, start_time: start, end_time: end }));
    setPage(1);
  }, []);

  const handleSearch = () => {
    setFilters((f) => ({ ...f, q: pendingQ }));
    setPage(1);
  };

  const handleExport = async () => {
    const rows: string[][] = [
      [
        t('LogExplorerPage.table.timestamp'),
        t('LogExplorerPage.table.type'),
        t('LogExplorerPage.table.severity'),
        t('LogExplorerPage.table.sourceIp'),
        t('LogExplorerPage.detail.hostnameLabel'),
        t('LogExplorerPage.table.message'),
      ],
    ];
    if (data) {
      for (const log of data.logs) {
        rows.push([
          log.timestamp,
          log.source_type,
          log.severity ?? '',
          log.source_ip,
          log.hostname ?? '',
          log.message,
        ]);
      }
    }
    // neutralize spreadsheet formula injection + escape embedded quotes.
    const esc = (c: unknown) => {
      let s = c == null ? '' : String(c);
      if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
      return `"${s.replace(/"/g, '""')}"`;
    };
    const csv = rows.map((r) => r.map(esc).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `collector-logs-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <PageHeader
        icon={ScrollText}
        title={t('LogExplorerPage.header.title')}
        description={t('LogExplorerPage.header.description')}
      />

      {isError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('LogExplorerPage.errors.loadFailed')}</span>
          </CardContent>
        </Card>
      )}

      {/* Filters */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Filter className="h-4 w-4" />
            {t('LogExplorerPage.filters.title')}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {/* Time presets */}
          <div className="flex flex-wrap gap-2">
            {PRESETS.map((p) => (
              <Button
                key={p.minutes}
                variant="outline"
                size="sm"
                onClick={() => applyPreset(p.minutes)}
                className="text-xs"
              >
                {t(`LogExplorerPage.presets.${p.labelKey}`)}
              </Button>
            ))}
          </div>

          {/* Custom time range */}
          <div className="grid gap-3 md:grid-cols-2">
            <div className="space-y-1">
              <Label className="text-xs">{t('LogExplorerPage.filters.startTime')}</Label>
              <Input
                type="datetime-local"
                value={toInputDatetime(filters.start_time)}
                onChange={(e) => {
                  setFilters((f) => ({
                    ...f,
                    start_time: fromInputDatetime(e.target.value),
                  }));
                  setPage(1);
                }}
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">{t('LogExplorerPage.filters.endTime')}</Label>
              <Input
                type="datetime-local"
                value={toInputDatetime(filters.end_time)}
                onChange={(e) => {
                  setFilters((f) => ({
                    ...f,
                    end_time: fromInputDatetime(e.target.value),
                  }));
                  setPage(1);
                }}
              />
            </div>
          </div>

          {/* Search + type + severity */}
          <div className="grid gap-3 md:grid-cols-4">
            <div className="col-span-2 flex gap-2">
              <Input
                placeholder={t('LogExplorerPage.filters.searchPlaceholder')}
                value={pendingQ}
                onChange={(e) => setPendingQ(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              />
              <Button onClick={handleSearch} size="icon" variant="outline">
                <Search className="h-4 w-4" />
              </Button>
            </div>
            <Select
              value={filters.source_type || 'all'}
              onValueChange={(v) => {
                setFilters((f) => ({ ...f, source_type: v === 'all' ? '' : v }));
                setPage(1);
              }}
            >
              <SelectTrigger>
                <SelectValue placeholder={t('LogExplorerPage.filters.allTypes')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('LogExplorerPage.filters.allTypes')}</SelectItem>
                <SelectItem value="syslog">{t('LogExplorerPage.filters.typeSyslog')}</SelectItem>
                <SelectItem value="snmp_trap">{t('LogExplorerPage.filters.typeSnmpTrap')}</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={filters.severity || 'all'}
              onValueChange={(v) => {
                setFilters((f) => ({ ...f, severity: v === 'all' ? '' : v }));
                setPage(1);
              }}
            >
              <SelectTrigger>
                <SelectValue placeholder={t('LogExplorerPage.filters.allSeverities')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('LogExplorerPage.filters.allSeverities')}</SelectItem>
                {['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'].map(
                  (s) => (
                    <SelectItem key={s} value={s}>
                      {t(`LogExplorerPage.severity.${s}`)}
                    </SelectItem>
                  )
                )}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">
              {data
                ? t('LogExplorerPage.results.count', { total: data.total.toLocaleString() })
                : t('LogExplorerPage.results.title')}
              {isFetching && !isLoading && (
                <Loader2 className="ml-2 inline h-3.5 w-3.5 animate-spin" />
              )}
            </CardTitle>
            <Button variant="outline" size="sm" onClick={handleExport} disabled={!data?.logs.length}>
              <Download className="mr-2 h-4 w-4" />
              {t('LogExplorerPage.actions.exportCsv')}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 8 }).map((_, i) => (
                <div key={i} className="flex items-center gap-4">
                  <Skeleton className="h-4 w-4" />
                  <Skeleton className="h-4 w-40" />
                  <Skeleton className="h-4 w-16" />
                  <Skeleton className="h-4 w-20" />
                  <Skeleton className="h-4 w-32" />
                  <Skeleton className="h-4 flex-1" />
                </div>
              ))}
            </div>
          ) : data && data.logs.length > 0 ? (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-8" />
                    <TableHead className="w-40">{t('LogExplorerPage.table.timestamp')}</TableHead>
                    <TableHead className="w-20">{t('LogExplorerPage.table.type')}</TableHead>
                    <TableHead className="w-28">{t('LogExplorerPage.table.severity')}</TableHead>
                    <TableHead className="w-32">{t('LogExplorerPage.table.sourceIp')}</TableHead>
                    <TableHead>{t('LogExplorerPage.table.message')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.logs.map((log) => (
                    <>
                      <TableRow
                        key={log.id}
                        className="cursor-pointer hover:bg-muted/50"
                        onClick={() =>
                          setExpandedId(expandedId === log.id ? null : log.id)
                        }
                      >
                        <TableCell className="w-8 py-2">
                          {expandedId === log.id ? (
                            <ChevronDown className="h-4 w-4 text-muted-foreground" />
                          ) : (
                            <ChevronRight className="h-4 w-4 text-muted-foreground" />
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {new Date(log.timestamp).toLocaleString()}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">
                            {log.source_type === 'snmp_trap'
                              ? t('LogExplorerPage.table.typeSnmpShort')
                              : t('LogExplorerPage.table.typeSyslogShort')}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <SeverityBadge severity={log.severity} />
                        </TableCell>
                        <TableCell className="font-mono text-xs">{log.source_ip}</TableCell>
                        <TableCell className="max-w-0 truncate text-sm">
                          {log.hostname && (
                            <span className="mr-2 font-medium">{log.hostname}</span>
                          )}
                          <span className="text-muted-foreground">{log.message}</span>
                        </TableCell>
                      </TableRow>
                      {expandedId === log.id && <LogDetailRow key={`${log.id}-detail`} log={log} />}
                    </>
                  ))}
                </TableBody>
              </Table>

              {/* Pagination */}
              {data.pages > 1 && (
                <div className="flex items-center justify-between border-t px-4 py-3">
                  <p className="text-xs text-muted-foreground">
                    {t('LogExplorerPage.pagination.pageOf', { page: data.page, pages: data.pages })}
                  </p>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setPage((p) => Math.max(1, p - 1))}
                      disabled={page === 1}
                    >
                      {t('LogExplorerPage.pagination.previous')}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setPage((p) => Math.min(data.pages, p + 1))}
                      disabled={page === data.pages}
                    >
                      {t('LogExplorerPage.pagination.next')}
                    </Button>
                  </div>
                </div>
              )}
            </>
          ) : (
            <EmptyState
              icon={FileText}
              title={t('LogExplorerPage.empty.title')}
              description={t('LogExplorerPage.empty.description')}
              variant="compact"
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
