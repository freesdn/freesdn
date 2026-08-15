// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * AgentDiscoveriesTab, shows the persistent `devices.discovered_hosts`
 * table populated by remote agents + GUI-triggered scans pushed via
 * POST /discovery/results.
 *
 * Distinct from the "Network Scan" tab (which shows the current scan's
 * results from `discovery_scan_results`). This tab is the cross-scan
 * device queue an operator works from to onboard new hosts.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { CheckCircle2, ExternalLink, Loader2, RefreshCw, Search, Microscope } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { discoveryApi, type AgentDiscoveredHost } from '@/lib/api/discovery';
import { agentsApi } from '@/lib/api/agents';
import { useToast } from '@/hooks/use-toast';

interface Props {
  siteId?: string;
}

export function AgentDiscoveriesTab({ siteId }: Props) {
  const { t } = useTranslation('common');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showAdopted, setShowAdopted] = useState(false);
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const { data: hosts = [], isLoading, isError, refetch } = useQuery({
    queryKey: ['discovered-hosts', siteId, showAdopted],
    queryFn: async () => {
      const resp = await discoveryApi.listDiscoveredHosts({
        site_id: siteId,
        show_adopted: showAdopted,
        limit: 500,
      });
      return resp.data;
    },
    enabled: !!siteId,
    refetchInterval: 30_000,
  });

  const fingerprintMutation = useMutation({
    mutationFn: async (host: AgentDiscoveredHost) => {
      if (!host.discovered_by_agent_id) {
        throw new Error(t('AgentDiscoveriesTab.errors.noAgentForProbe'));
      }
      const resp = await agentsApi.fingerprintHost(
        host.discovered_by_agent_id,
        host.ip_address,
      );
      return { host, data: resp.data };
    },
    onSuccess: ({ host, data }) => {
      toast({
        title: t('AgentDiscoveriesTab.toast.probeDispatched.title'),
        description: t('AgentDiscoveriesTab.toast.probeDispatched.description', {
          ip: host.ip_address,
          taskId: data.task_id.slice(0, 8),
        }),
      });
    },
    onError: (err: any) => {
      toast({
        title: t('AgentDiscoveriesTab.toast.probeFailed.title'),
        description: err?.response?.data?.detail || String(err?.message || err),
        variant: 'destructive',
      });
    },
  });

  const adoptMutation = useMutation({
    mutationFn: async (toAdopt: AgentDiscoveredHost[]) => {
      // driver_id is omitted intentionally, backend auto-matches per host
      // and falls back to "generic" for hosts that don't score a confident
      // vendor adapter match.
      const devices = toAdopt.map((h) => ({
        ip_address: h.ip_address,
        name: h.hostname || `discovered-${h.ip_address}`,
        site_id: h.site_id,
        device_type: h.device_type || 'other',
        ...(h.mac_address ? { mac_address: h.mac_address } : {}),
      }));
      const resp = await discoveryApi.bulkAdoptDevices(devices);
      return resp.data;
    },
    onSuccess: (data) => {
      toast({
        title: t('AgentDiscoveriesTab.toast.adoptComplete.title'),
        description: t('AgentDiscoveriesTab.toast.adoptComplete.description', {
          succeeded: data.succeeded,
          total: data.total,
          failed: data.failed,
        }),
      });
      setSelected(new Set());
      queryClient.invalidateQueries({ queryKey: ['discovered-hosts'] });
    },
    onError: (err: any) => {
      toast({
        title: t('AgentDiscoveriesTab.toast.adoptFailed.title'),
        description: err?.response?.data?.detail || String(err),
        variant: 'destructive',
      });
    },
  });

  const filtered = hosts.filter((h) => {
    if (!filter) return true;
    const q = filter.toLowerCase();
    return (
      h.ip_address.toLowerCase().includes(q) ||
      (h.mac_address || '').toLowerCase().includes(q) ||
      (h.hostname || '').toLowerCase().includes(q) ||
      (h.vendor || '').toLowerCase().includes(q)
    );
  });

  const adoptable = filtered.filter((h) => !h.is_adopted);
  const allSelected =
    adoptable.length > 0 && adoptable.every((h) => selected.has(h.id));

  const toggleAll = () => {
    if (allSelected) {
      setSelected(new Set());
    } else {
      setSelected(new Set(adoptable.map((h) => h.id)));
    }
  };

  const toggleRow = (id: string) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next);
  };

  const adoptSelected = () => {
    const toAdopt = adoptable.filter((h) => selected.has(h.id));
    if (toAdopt.length === 0) return;
    adoptMutation.mutate(toAdopt);
  };

  if (!siteId) {
    return (
      <Card>
        <CardContent className="p-6 text-sm text-muted-foreground">
          {t('AgentDiscoveriesTab.selectSitePrompt')}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            {t('AgentDiscoveriesTab.title')}
            <Badge variant="secondary">{hosts.length}</Badge>
          </CardTitle>
          <div className="flex items-center gap-2">
            <label className="flex items-center gap-2 text-sm text-muted-foreground">
              <Checkbox
                checked={showAdopted}
                onCheckedChange={(v) => setShowAdopted(!!v)}
              />
              {t('AgentDiscoveriesTab.showAdopted')}
            </label>
            <Button variant="outline" size="sm" onClick={() => refetch()}>
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-2">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder={t('AgentDiscoveriesTab.filterPlaceholder')}
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="pl-8"
            />
          </div>
          <Button
            onClick={adoptSelected}
            disabled={selected.size === 0 || adoptMutation.isPending}
          >
            {adoptMutation.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : null}
            {selected.size > 0
              ? t('AgentDiscoveriesTab.adoptCount', { count: selected.size })
              : t('AgentDiscoveriesTab.adoptSelected')}
          </Button>
        </div>

        {isError ? (
          <div className="text-sm text-destructive p-4">
            {t('AgentDiscoveriesTab.loadError')}
          </div>
        ) : isLoading ? (
          <div className="text-sm text-muted-foreground p-4">{t('AgentDiscoveriesTab.loading')}</div>
        ) : filtered.length === 0 ? (
          <div className="text-sm text-muted-foreground p-4">
            {t('AgentDiscoveriesTab.empty')}
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10">
                  <Checkbox
                    checked={allSelected}
                    onCheckedChange={toggleAll}
                    aria-label={t('AgentDiscoveriesTab.selectAllAria')}
                  />
                </TableHead>
                <TableHead>{t('AgentDiscoveriesTab.columns.ip')}</TableHead>
                <TableHead>{t('AgentDiscoveriesTab.columns.mac')}</TableHead>
                <TableHead>{t('AgentDiscoveriesTab.columns.vendor')}</TableHead>
                <TableHead>{t('AgentDiscoveriesTab.columns.hostname')}</TableHead>
                <TableHead>{t('AgentDiscoveriesTab.columns.sources')}</TableHead>
                <TableHead>{t('AgentDiscoveriesTab.columns.status')}</TableHead>
                <TableHead className="text-right">{t('AgentDiscoveriesTab.columns.probe')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((h) => (
                <TableRow key={h.id} className={h.is_adopted ? 'opacity-60' : ''}>
                  <TableCell>
                    {h.is_adopted ? null : (
                      <Checkbox
                        checked={selected.has(h.id)}
                        onCheckedChange={() => toggleRow(h.id)}
                      />
                    )}
                  </TableCell>
                  <TableCell className="font-mono">{h.ip_address}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {h.mac_address || '-'}
                  </TableCell>
                  <TableCell>{h.vendor || '-'}</TableCell>
                  <TableCell className="text-xs">{h.hostname || '-'}</TableCell>
                  <TableCell>
                    <div className="flex gap-1 flex-wrap">
                      {(h.discovered_via || []).map((s) => (
                        <Badge key={s} variant="outline" className="text-xs">
                          {s}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>
                    {h.is_adopted ? (
                      h.adopted_device_id ? (
                        <Link
                          to={`/devices/${h.adopted_device_id}`}
                          className="flex items-center gap-1 text-emerald-600 hover:underline text-xs"
                        >
                          <CheckCircle2 className="h-3.5 w-3.5" />
                          {t('AgentDiscoveriesTab.status.adopted')}
                          <ExternalLink className="h-3 w-3" />
                        </Link>
                      ) : h.known_as ? (
                        // FreeSDN already knows this IP/MAC (a controller
                        // appliance or a controller-synced device), it's
                        // not a brand-new host even if not directly adopted.
                        <span
                          className="flex items-center gap-1 text-xs text-violet-600 dark:text-violet-400"
                          title={t('AgentDiscoveriesTab.status.knownTooltip', {
                            name: h.known_as.name,
                            detail: h.known_as.detail,
                          })}
                        >
                          <CheckCircle2 className="h-3.5 w-3.5" />
                          {t('AgentDiscoveriesTab.status.known', { detail: h.known_as.detail })}
                        </span>
                      ) : (
                        <Badge variant="secondary">{t('AgentDiscoveriesTab.status.adopted')}</Badge>
                      )
                    ) : h.known_as ? (
                      <span
                        className="flex items-center gap-1 text-xs text-violet-600 dark:text-violet-400"
                        title={t('AgentDiscoveriesTab.status.knownTooltip', {
                          name: h.known_as.name,
                          detail: h.known_as.detail,
                        })}
                      >
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        {t('AgentDiscoveriesTab.status.known', { detail: h.known_as.detail })}
                      </span>
                    ) : (
                      <Badge variant="outline">{t('AgentDiscoveriesTab.status.new')}</Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    {h.discovered_by_agent_id ? (
                      <Button
                        size="sm"
                        variant="ghost"
                        title={t('AgentDiscoveriesTab.probeTooltip')}
                        onClick={() => fingerprintMutation.mutate(h)}
                        disabled={
                          fingerprintMutation.isPending
                          && fingerprintMutation.variables?.id === h.id
                        }
                      >
                        <Microscope className="h-4 w-4" />
                      </Button>
                    ) : null}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
