// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Certificates Tab
 * Shows TLS certificate info for each Proxmox node with renew/upload actions.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueries } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { Shield, Upload, RefreshCw, Trash2 } from 'lucide-react';
import { hypervisorApi } from '@/lib/api';
import { CertificateOperationDialog } from './dialogs/CertificateOperationDialog';
import type { HypervisorNode } from '@/lib/api';

interface CertificatesTabProps {
  controllerId: string;
  nodes: HypervisorNode[];
  onTracked: () => void;
}

interface CertInfo {
  filename?: string;
  subject?: string;
  issuer?: string;
  fingerprint?: string;
  notbefore?: string | number;
  notafter?: string | number;
  'public-key-type'?: string;
  'public-key-bits'?: number;
  san?: string[];
}

function formatCertDate(val: string | number | undefined): string {
  if (!val) return '--';
  const d = typeof val === 'number' ? new Date(val * 1000) : new Date(val);
  return Number.isFinite(d.getTime()) ? d.toLocaleDateString() : '--';
}

function daysUntilExpiry(val: string | number | undefined): number | null {
  if (!val) return null;
  const d = typeof val === 'number' ? new Date(val * 1000) : new Date(val);
  return Number.isFinite(d.getTime()) ? Math.floor((d.getTime() - Date.now()) / 86400000) : null;
}

function expiryBadge(val: string | number | undefined, t: (key: string, options?: Record<string, unknown>) => string) {
  const days = daysUntilExpiry(val);
  if (days === null) return <Badge variant="secondary">{t('CertificatesTab.status.unknown')}</Badge>;
  if (days < 0) return <Badge variant="destructive">{t('CertificatesTab.status.expired')}</Badge>;
  if (days < 30) return <Badge className="bg-amber-500 text-white">{t('CertificatesTab.status.daysLeft', { days })}</Badge>;
  return <Badge variant="secondary">{t('CertificatesTab.status.daysLeft', { days })}</Badge>;
}

export function CertificatesTab({ controllerId, nodes, onTracked }: CertificatesTabProps) {
  const { t } = useTranslation('hypervisor');
  const [intent, setIntent] = useState<{ node: string; action: 'upload' | 'delete' | 'renew' } | null>(null);

  // Fetch certs for all nodes
  const nodeQueryResults = useQueries({
    queries: nodes.map((n) => ({
      queryKey: ['hypervisor', 'certificates', controllerId, n.node],
      queryFn: () => hypervisorApi.getNodeCertificates(controllerId, n.node),
      enabled: !!controllerId,
    })),
  });

  const isLoading = nodeQueryResults.some((q) => q.isLoading);
  const hasError = nodeQueryResults.some((q) => q.isError);

  // Flatten certs with node info
  const allCerts: (CertInfo & { _node: string })[] = [];
  for (let i = 0; i < nodes.length; i++) {
    const items = (nodeQueryResults[i]?.data?.data as CertInfo[] | undefined) || [];
    for (const cert of items) {
      allCerts.push({ ...cert, _node: nodes[i].node });
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (hasError) {
    return <ErrorState message={t('CertificatesTab.error.fetchFailed')} />;
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-sm">{t('CertificatesTab.title')}</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {allCerts.length === 0 ? (
            <div className="py-4">
              <EmptyState icon={Shield} title={t('CertificatesTab.empty.title')} description={t('CertificatesTab.empty.description')} />
            </div>
          ) : (
            <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('CertificatesTab.columns.node')}</TableHead>
                  <TableHead>{t('CertificatesTab.columns.subject')}</TableHead>
                  <TableHead>{t('CertificatesTab.columns.issuer')}</TableHead>
                  <TableHead>{t('CertificatesTab.columns.fingerprint')}</TableHead>
                  <TableHead>{t('CertificatesTab.columns.validFrom')}</TableHead>
                  <TableHead>{t('CertificatesTab.columns.expires')}</TableHead>
                  <TableHead>{t('CertificatesTab.columns.status')}</TableHead>
                  <TableHead className="text-right">{t('CertificatesTab.columns.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {allCerts.map((c, i) => (
                  <TableRow key={`${c._node}-${c.filename}-${i}`}>
                    <TableCell>
                      <Badge variant="outline">{c._node}</Badge>
                    </TableCell>
                    <TableCell className="text-sm max-w-48 truncate">{c.subject || '--'}</TableCell>
                    <TableCell className="text-sm max-w-48 truncate text-muted-foreground">{c.issuer || '--'}</TableCell>
                    <TableCell className="font-mono text-xs max-w-32 truncate">{c.fingerprint || '--'}</TableCell>
                    <TableCell className="text-sm">{formatCertDate(c.notbefore)}</TableCell>
                    <TableCell className="text-sm">{formatCertDate(c.notafter)}</TableCell>
                    <TableCell>{expiryBadge(c.notafter, t)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        {c.filename === 'pveproxy-ssl.pem' && <><Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setIntent({ node: c._node, action: 'renew' })}
                        >
                          <RefreshCw className="h-3 w-3 mr-1" />
                          {t('CertificatesTab.actions.renew')}
                        </Button><Button variant="ghost" size="sm" onClick={() => setIntent({ node: c._node, action: 'delete' })}><Trash2 className="h-3 w-3 mr-1" />{t('CertificateOperationDialog.remove')}</Button></>}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setIntent({ node: c._node, action: 'upload' })}
                        >
                          <Upload className="h-3 w-3 mr-1" />
                          {t('CertificatesTab.actions.upload')}
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {intent && <CertificateOperationDialog controllerId={controllerId} node={intent.node} action={intent.action} onClose={() => setIntent(null)} onTracked={onTracked} />}
    </div>
  );
}
