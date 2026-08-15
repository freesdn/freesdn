// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Certificates Tab
 * Shows TLS certificate info for each Proxmox node with renew/upload actions.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueries, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { DestructiveConfirmDialog } from '@/components/ui/destructive-confirm-dialog';
import { Shield, Upload, RefreshCw } from 'lucide-react';
import { hypervisorApi } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import type { HypervisorNode } from '@/lib/api';

interface CertificatesTabProps {
  controllerId: string;
  nodes: HypervisorNode[];
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
  return d.toLocaleDateString();
}

function daysUntilExpiry(val: string | number | undefined): number | null {
  if (!val) return null;
  const d = typeof val === 'number' ? new Date(val * 1000) : new Date(val);
  return Math.floor((d.getTime() - Date.now()) / 86400000);
}

function expiryBadge(val: string | number | undefined, t: (key: string, options?: Record<string, unknown>) => string) {
  const days = daysUntilExpiry(val);
  if (days === null) return <Badge variant="secondary">{t('CertificatesTab.status.unknown')}</Badge>;
  if (days < 0) return <Badge variant="destructive">{t('CertificatesTab.status.expired')}</Badge>;
  if (days < 30) return <Badge className="bg-amber-500 text-white">{t('CertificatesTab.status.daysLeft', { days })}</Badge>;
  return <Badge variant="secondary">{t('CertificatesTab.status.daysLeft', { days })}</Badge>;
}

export function CertificatesTab({ controllerId, nodes }: CertificatesTabProps) {
  const { t } = useTranslation('hypervisor');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [uploadDialog, setUploadDialog] = useState<string | null>(null);
  // Typed-confirm target for ACME renew (replaces native confirm()).
  const [renewTarget, setRenewTarget] = useState<string | null>(null);
  const [certPem, setCertPem] = useState('');
  const [keyPem, setKeyPem] = useState('');
  const [force, setForce] = useState(false);
  const [restart, setRestart] = useState(true);

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

  const renewMutation = useMutation({
    mutationFn: (node: string) => hypervisorApi.renewAcmeCertificate(controllerId, node),
    onSuccess: (_data, node) => {
      toast({ title: t('CertificatesTab.toast.renewStarted.title'), description: t('CertificatesTab.toast.renewStarted.description', { node }) });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'certificates', controllerId, node] });
    },
    onError: () => {
      toast({ title: t('CertificatesTab.toast.renewFailed.title'), description: t('CertificatesTab.toast.renewFailed.description'), variant: 'destructive' });
    },
  });

  const uploadMutation = useMutation({
    mutationFn: (node: string) =>
      hypervisorApi.uploadCustomCertificate(controllerId, node, {
        certificates: certPem,
        key: keyPem,
        force,
        restart,
      }),
    onSuccess: (_data, node) => {
      toast({ title: t('CertificatesTab.toast.uploadSuccess.title'), description: t('CertificatesTab.toast.uploadSuccess.description', { node }) });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'certificates', controllerId, node] });
      setUploadDialog(null);
      setCertPem('');
      setKeyPem('');
    },
    onError: () => {
      toast({ title: t('CertificatesTab.toast.uploadFailed.title'), description: t('CertificatesTab.toast.uploadFailed.description'), variant: 'destructive' });
    },
  });

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
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setRenewTarget(c._node)}
                          disabled={renewMutation.isPending}
                        >
                          <RefreshCw className="h-3 w-3 mr-1" />
                          {t('CertificatesTab.actions.renew')}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setUploadDialog(c._node)}
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

      {/* Upload Custom Certificate Dialog */}
      <Dialog open={!!uploadDialog} onOpenChange={(open) => {
        setUploadDialog(open ? uploadDialog : null);
        if (!open) {
          setCertPem('');
          setKeyPem('');
        }
      }}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('CertificatesTab.dialog.title')}</DialogTitle>
            <DialogDescription>{t('CertificatesTab.dialog.description', { node: uploadDialog })}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="cert-pem">{t('CertificatesTab.dialog.certLabel')}</Label>
              <textarea
                id="cert-pem"
                className="mt-1 w-full rounded-md border bg-transparent px-3 py-2 text-sm font-mono min-h-[100px]"
                value={certPem}
                onChange={(e) => setCertPem(e.target.value)}
                placeholder="-----BEGIN CERTIFICATE-----"
              />
            </div>
            <div>
              <Label htmlFor="key-pem">{t('CertificatesTab.dialog.keyLabel')}</Label>
              <textarea
                id="key-pem"
                className="mt-1 w-full rounded-md border bg-transparent px-3 py-2 text-sm font-mono min-h-[100px]"
                value={keyPem}
                onChange={(e) => setKeyPem(e.target.value)}
                placeholder="-----BEGIN PRIVATE KEY-----"
              />
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <Checkbox id="cert-force" checked={force} onCheckedChange={(v) => setForce(!!v)} />
                <Label htmlFor="cert-force" className="text-sm">{t('CertificatesTab.dialog.forceOverwrite')}</Label>
              </div>
              <div className="flex items-center gap-2">
                <Checkbox id="cert-restart" checked={restart} onCheckedChange={(v) => setRestart(!!v)} />
                <Label htmlFor="cert-restart" className="text-sm">{t('CertificatesTab.dialog.restartServices')}</Label>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUploadDialog(null)}>{t('CertificatesTab.actions.cancel')}</Button>
            <Button
              disabled={!certPem || !keyPem || uploadMutation.isPending}
              onClick={() => { if (uploadDialog) uploadMutation.mutate(uploadDialog); }}
            >
              {t('CertificatesTab.actions.uploadCertificate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Typed-confirm dialog for ACME renew (replaces native confirm()) */}
      <DestructiveConfirmDialog
        open={renewTarget !== null}
        onOpenChange={(o) => { if (!o) setRenewTarget(null); }}
        title={t('CertificatesTab.actions.renew')}
        description={t('CertificatesTab.confirm.renew', { node: renewTarget ?? '' })}
        confirmationText={renewTarget ?? ''}
        confirmLabel={t('CertificatesTab.actions.renew')}
        isPending={renewMutation.isPending}
        onConfirm={() => {
          if (renewTarget) renewMutation.mutate(renewTarget);
          setRenewTarget(null);
        }}
      />
    </div>
  );
}
