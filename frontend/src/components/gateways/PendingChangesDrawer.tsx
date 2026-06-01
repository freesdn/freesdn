// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PendingChangesDrawer, closure.
 *
 * Every "save" button in the gateway tabs stages a row in
 * ``adapter_pending_changes`` and shows a toast saying "the change
 * applies via the Pending Changes panel". This component IS that
 * panel, without it, operators had no way to push staged writes
 * to the live device short of curl-ing the apply endpoint.
 *
 * UX:
 *   - Pending section (expanded): per-row Apply + Discard buttons
 *     and a "Apply all" bulk action at the top.
 *   - Recently applied (collapsed): last ~20 applied rows.
 *   - Failed (only shown if non-empty): shows failure_reason.
 *
 * Safety:
 *   - Apply always sends ``{force: true}`` server-side. The other
 *     half of the dual-gate is the env var ``OMADA_READ_ONLY=false``,
 *     which we surface as a read-only banner when the server refuses.
 *   - Catastrophic features (reboot, backup restore, firmware install,
 *     destructive deletes) require a typed ``APPLY`` confirmation.
 *   - Bulk apply requires ``APPLY ALL`` typed, then runs sequentially
 *     and stops on first error so the operator sees exactly where it
 *     broke.
 */
import { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query';
import { formatDistanceToNow } from 'date-fns';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ClipboardList,
  Loader2,
  RefreshCw,
  ShieldAlert,
  Trash2,
  XCircle,
} from 'lucide-react';

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { EmptyState } from '@/components/ui/empty-state';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import {
  applyPendingChange,
  describeApplyError,
  discardPendingChange,
  listChangesForGateway,
  type GatewayVendor,
  type PendingChangeResponse,
} from '@/lib/api';
import { cn } from '@/lib/utils';

// ── Catastrophic feature prefixes ─────────────────────────────────────
//
// Mirror of backend ``_CATASTROPHIC_FEATURE_PREFIXES`` (the subset the
// gateway tabs can stage). Used to gate apply behind a typed-confirm
// dialog regardless of the operation column (delete is dangerous, but
// so is a reboot/restore even though those are technically "create"
// ops on a system feature).

const CATASTROPHIC_FEATURE_PREFIXES: readonly string[] = [
  // MikroTik
  'mikrotik.system.reboot',
  'mikrotik.system.shutdown',
  'mikrotik.system.backup_load',
  'mikrotik.system.tool_fetch',
  'mikrotik.system.export_config',
  'mikrotik.system.firmware.install',
  'mikrotik.system.package.uninstall',
  'mikrotik.system.backup.restore',
  // OPNsense / pfSense
  'opnsense.system.reboot',
  'opnsense.system.halt',
  'opnsense.system.firmware_update',
  'opnsense.system.firmware_upgrade',
  'opnsense.system.backup_restore',
  'opnsense.system.config_restore',
  'pfsense.system.reboot',
  'pfsense.system.halt',
  'pfsense.system.firmware_update',
  'pfsense.system.firmware_upgrade',
  'pfsense.system.backup_restore',
  'pfsense.system.config_restore',
  // UniFi, device-level destructive ops (audit,
  // closure). Restart cycles the AP/switch for 60-90s; disable
  // leaves it offline indefinitely; upgrade flashes firmware + reboots.
  // All require typed-APPLY + site_admin per the backend gate
  // (``adapter_unifi_preflight._CATASTROPHIC_FEATURES``). client.forget
  // is a delete op so it's caught by the operation branch below.
  'unifi.devices.restart',
  'unifi.devices.disable',
  'unifi.devices.upgrade',
];

export function isCatastrophic(change: PendingChangeResponse): boolean {
  if (CATASTROPHIC_FEATURE_PREFIXES.some((p) => change.feature.startsWith(p))) {
    return true;
  }
  // Any delete is at least "destructive enough" to deserve the typed
  // confirm. create/update can land via the simpler confirm.
  return change.operation === 'delete';
}

// ── Query keys ─────────────────────────────────────────────────────────

export const pendingChangesQueryKey = (
  vendor: GatewayVendor,
  gatewayId: string,
) => ['pending-changes', vendor, gatewayId] as const;

// ── Public props ───────────────────────────────────────────────────────

export interface PendingChangesDrawerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vendor: GatewayVendor;
  gatewayId: string;
  gatewayName: string;
  /**
   * Fired after a change is successfully applied (single or bulk). The parent
   * uses this to refresh its own device-state views — an apply mutates the
   * live device, so any cached entity lists (extensions, DIDs, …) are now
   * stale and should be refetched.
   */
  onApplied?: () => void;
}

// ── Component ──────────────────────────────────────────────────────────

export function PendingChangesDrawer({
  open,
  onOpenChange,
  vendor,
  gatewayId,
  gatewayName,
  onApplied,
}: PendingChangesDrawerProps) {
  const { t } = useTranslation('common');
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // We pull every status in one call. Service caps each domain at 200,
  // and the badge polls only pending so the count stays cheap.
  const query = useQuery({
    queryKey: pendingChangesQueryKey(vendor, gatewayId),
    queryFn: () => listChangesForGateway(vendor, gatewayId, { status: 'all' }),
    enabled: open && !!gatewayId,
    // Drawer is the operator's "what just happened?" view, refresh
    // often while open so an apply elsewhere shows up immediately.
    refetchInterval: open ? 5_000 : false,
    refetchOnWindowFocus: true,
    staleTime: 1_000,
  });

  const changes = useMemo(() => query.data ?? [], [query.data]);
  const pending = useMemo(
    () => changes.filter((c) => c.status === 'pending'),
    [changes],
  );
  const applying = useMemo(
    () => changes.filter((c) => c.status === 'applying'),
    [changes],
  );
  const applied = useMemo(
    () => changes.filter((c) => c.status === 'applied').slice(0, 20),
    [changes],
  );
  const failed = useMemo(
    () => changes.filter((c) => c.status === 'failed'),
    [changes],
  );

  // CRIT-2: "Apply all" is sequential
  // and treats a 200 from a reboot/firmware-install as success, but the
  // router is then mid-reboot/upgrade for 60-90s. Subsequent applies in
  // the loop fire against a router that can't answer, the loop bails on
  // the first 502, and the operator is left with a half-applied bulk
  // and no clean way to resume. Disable the bulk path entirely if any
  // catastrophic change is in the queue; force the operator to apply
  // those one-by-one (with the per-row typed-APPLY confirm) so the
  // ordering and timing decisions are explicit.
  const bulkHasCatastrophic = useMemo(
    () => pending.some(isCatastrophic),
    [pending],
  );

  // ── Banner: 403 read-only ───────────────────────────────────────────
  const [readOnlyBanner, setReadOnlyBanner] = useState<string | null>(null);

  // ── Confirm dialog state (per-row apply) ────────────────────────────
  const [confirmTarget, setConfirmTarget] =
    useState<PendingChangeResponse | null>(null);
  const [confirmText, setConfirmText] = useState('');
  const confirmRequiresTyped = confirmTarget
    ? isCatastrophic(confirmTarget)
    : false;
  const confirmReady = confirmRequiresTyped
    ? confirmText === 'APPLY'
    : true;

  // ── Discard dialog state ────────────────────────────────────────────
  const [discardTarget, setDiscardTarget] =
    useState<PendingChangeResponse | null>(null);

  // ── Bulk-apply dialog state ─────────────────────────────────────────
  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkConfirmText, setBulkConfirmText] = useState('');
  const [bulkProgress, setBulkProgress] = useState<{
    current: number;
    total: number;
    error?: string;
  } | null>(null);

  // ── Recently-applied collapsibles ───────────────────────────────────
  const [appliedOpen, setAppliedOpen] = useState(false);
  const [failedOpen, setFailedOpen] = useState(true);

  const invalidate = useCallback(() => {
    queryClient.invalidateQueries({
      queryKey: pendingChangesQueryKey(vendor, gatewayId),
    });
  }, [queryClient, vendor, gatewayId]);

  // ── Apply ──────────────────────────────────────────────────────────

  const applyMutation = useMutation({
    // Destructive/catastrophic changes (any delete + device restart/disable/
    // upgrade + client forget) ride the typed-APPLY confirm above; passing
    // ``confirmed: true`` for exactly those is the operator's apply-time sign-off
    // the backend vendor pre-flights require. Non-destructive applies omit it.
    mutationFn: (change: PendingChangeResponse) =>
      applyPendingChange(change.id, { confirmed: isCatastrophic(change) }),
    onSuccess: (_res, _change) => {
      toast({
        title: t('PendingChangesDrawer.toasts.applied.title'),
        description: t('PendingChangesDrawer.toasts.applied.description', {
          gatewayName,
        }),
      });
      invalidate();
      onApplied?.();
      setConfirmTarget(null);
      setConfirmText('');
      setReadOnlyBanner(null);
    },
    onError: (err) => {
      const info = describeApplyError(err);
      if (info.isReadOnly) {
        setReadOnlyBanner(info.message);
      }
      toast({
        title: t('PendingChangesDrawer.toasts.applyFailed.title'),
        description: info.vendorError || info.message,
        variant: 'destructive',
      });
      invalidate(); // pull the failed row's status from the server
      setConfirmTarget(null);
      setConfirmText('');
    },
  });

  // ── Discard ────────────────────────────────────────────────────────

  const discardMutation = useMutation({
    mutationFn: (changeId: string) => discardPendingChange(changeId),
    onSuccess: () => {
      toast({ title: t('PendingChangesDrawer.toasts.discarded.title') });
      invalidate();
      setDiscardTarget(null);
    },
    onError: (err) => {
      const info = describeApplyError(err);
      toast({
        title: t('PendingChangesDrawer.toasts.discardFailed.title'),
        description: info.message,
        variant: 'destructive',
      });
      setDiscardTarget(null);
    },
  });

  // ── Bulk apply ──────────────────────────────────────────────────────
  //
  // Sequential, stops on first error. We update progress state inline
  // so the dialog can show "Applying 2 / 5..." and the user can decide
  // whether to retry the rest after a fix.

  const runBulkApply = useCallback(async () => {
    setBulkProgress({ current: 0, total: pending.length });
    for (let i = 0; i < pending.length; i++) {
      const change = pending[i];
      setBulkProgress({ current: i + 1, total: pending.length });
      try {
        // Bulk is disabled when any catastrophic change is queued, so these are
        // all non-destructive; pass confirmed for parity with the per-row path.
        await applyPendingChange(change.id, { confirmed: isCatastrophic(change) });
      } catch (err) {
        const info = describeApplyError(err);
        if (info.isReadOnly) setReadOnlyBanner(info.message);
        setBulkProgress({
          current: i + 1,
          total: pending.length,
          error: info.vendorError || info.message,
        });
        invalidate();
        // Changes before the failure index did apply to the device — refresh.
        if (i > 0) onApplied?.();
        return;
      }
    }
    setBulkProgress(null);
    setBulkOpen(false);
    setBulkConfirmText('');
    toast({
      title: t('PendingChangesDrawer.toasts.allApplied.title'),
      description: t('PendingChangesDrawer.toasts.allApplied.description', {
        count: pending.length,
        gatewayName,
      }),
    });
    invalidate();
    onApplied?.();
  }, [pending, invalidate, onApplied, toast, gatewayName, t]);

  // ── Render helpers ──────────────────────────────────────────────────

  function renderChange(
    change: PendingChangeResponse,
    kind: 'pending' | 'applied' | 'failed' | 'applying',
  ) {
    return (
      <li
        key={change.id}
        className="border border-border rounded-lg p-3 space-y-2"
      >
        <div className="flex items-start justify-between gap-2">
          <div className="space-y-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <OperationBadge operation={change.operation} />
              <code className="text-xs font-mono text-foreground break-all">
                {change.feature}
              </code>
            </div>
            <div className="text-xs text-muted-foreground">
              {change.target_id ? (
                <span>
                  {t('PendingChangesDrawer.change.targetLabel')}{' '}
                  <code className="font-mono">{change.target_id}</code>
                </span>
              ) : (
                <span>{t('PendingChangesDrawer.change.noTargetId')}</span>
              )}
              {' · '}
              <span title={change.created_at}>
                {formatDistanceToNow(new Date(change.created_at), {
                  addSuffix: true,
                })}
              </span>
            </div>
          </div>
          {kind === 'pending' && (
            <div className="flex items-center gap-1 shrink-0">
              <Button
                size="sm"
                variant="default"
                onClick={() => {
                  setConfirmTarget(change);
                  setConfirmText('');
                }}
                aria-label={t('PendingChangesDrawer.change.applyAria', {
                  feature: change.feature,
                })}
                disabled={applyMutation.isPending}
              >
                {t('PendingChangesDrawer.actions.apply')}
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => setDiscardTarget(change)}
                aria-label={t('PendingChangesDrawer.change.discardAria', {
                  feature: change.feature,
                })}
                disabled={discardMutation.isPending}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
          )}
        </div>

        <details className="text-xs">
          <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
            {t('PendingChangesDrawer.change.payload')}
          </summary>
          <pre className="mt-2 p-2 rounded bg-muted text-xs overflow-x-auto whitespace-pre-wrap break-all">
            {JSON.stringify(change.payload, null, 2)}
          </pre>
        </details>

        {kind === 'failed' && change.failure_reason && (
          <p className="text-xs text-destructive">
            <ShieldAlert className="inline h-3 w-3 mr-1" />
            {change.failure_reason}
          </p>
        )}

        {kind === 'applied' && change.applied_response && (
          <details className="text-xs">
            <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
              {t('PendingChangesDrawer.change.applyResponse')}
            </summary>
            <pre className="mt-2 p-2 rounded bg-muted text-xs overflow-x-auto whitespace-pre-wrap break-all">
              {JSON.stringify(change.applied_response, null, 2)}
            </pre>
          </details>
        )}
      </li>
    );
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-[90vw] sm:max-w-xl flex flex-col gap-4"
        aria-describedby="pending-changes-description"
      >
        <SheetHeader className="border-b border-border pb-3">
          <div className="flex items-center justify-between gap-2">
            <SheetTitle className="flex items-center gap-2">
              <ClipboardList className="h-5 w-5" />
              {t('PendingChangesDrawer.title')}
            </SheetTitle>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => query.refetch()}
              disabled={query.isFetching}
              aria-label={t('PendingChangesDrawer.refreshAria')}
            >
              <RefreshCw
                className={cn(
                  'h-4 w-4',
                  query.isFetching && 'animate-spin',
                )}
              />
            </Button>
          </div>
          <SheetDescription id="pending-changes-description">
            {t('PendingChangesDrawer.description.before')}{' '}
            <span className="font-medium">{gatewayName}</span>
            {t('PendingChangesDrawer.description.after')}
          </SheetDescription>
        </SheetHeader>

        <div className="flex-1 overflow-y-auto space-y-4 pr-1">
          {readOnlyBanner && (
            <Alert variant="destructive">
              <ShieldAlert className="h-4 w-4" />
              <AlertTitle>{t('PendingChangesDrawer.readOnly.title')}</AlertTitle>
              <AlertDescription className="space-y-1">
                <p>{readOnlyBanner}</p>
                <p className="text-xs">
                  {t('PendingChangesDrawer.readOnly.setPrefix')}{' '}
                  <code className="font-mono">ADAPTER_READ_ONLY=false</code>{' '}
                  {t('PendingChangesDrawer.readOnly.legacyPrefix')}{' '}
                  <code className="font-mono">OMADA_READ_ONLY=false</code>
                  {t('PendingChangesDrawer.readOnly.middle')}{' '}
                  <code className="font-mono">site_admin</code>.
                </p>
              </AlertDescription>
            </Alert>
          )}

          {query.isError && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>{t('PendingChangesDrawer.loadError.title')}</AlertTitle>
              <AlertDescription>
                {(query.error as Error)?.message ||
                  t('PendingChangesDrawer.loadError.unknown')}
              </AlertDescription>
            </Alert>
          )}

          {query.isLoading ? (
            <div className="flex items-center gap-2 text-muted-foreground py-8 justify-center">
              <Loader2 className="h-4 w-4 animate-spin" />
              <span>{t('PendingChangesDrawer.loading')}</span>
            </div>
          ) : pending.length === 0 && applied.length === 0 && failed.length === 0 ? (
            <EmptyState
              icon={ClipboardList}
              title={t('PendingChangesDrawer.empty.title')}
              description={t('PendingChangesDrawer.empty.description')}
              variant="compact"
            />
          ) : (
            <>
              {/* Pending */}
              <section aria-label={t('PendingChangesDrawer.sections.pending.aria')}>
                <header className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-semibold flex items-center gap-2">
                    {t('PendingChangesDrawer.sections.pending.heading')}
                    <Badge variant="default">{pending.length}</Badge>
                  </h3>
                  {pending.length > 1 && (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => {
                        setBulkOpen(true);
                        setBulkConfirmText('');
                        setBulkProgress(null);
                      }}
                      disabled={
                        applyMutation.isPending || bulkHasCatastrophic
                      }
                      title={
                        bulkHasCatastrophic
                          ? t('PendingChangesDrawer.sections.pending.bulkDisabledTooltip')
                          : undefined
                      }
                    >
                      {t('PendingChangesDrawer.actions.applyAll')}
                    </Button>
                  )}
                </header>
                {pending.length === 0 ? (
                  <p className="text-xs text-muted-foreground italic">
                    {t('PendingChangesDrawer.sections.pending.nothingStaged')}
                  </p>
                ) : (
                  <ul className="space-y-2">
                    {pending.map((c) => renderChange(c, 'pending'))}
                  </ul>
                )}
              </section>

              {/* Applying (transient, shows the row mid-apply) */}
              {applying.length > 0 && (
                <section aria-label={t('PendingChangesDrawer.sections.applying.aria')}>
                  <header className="flex items-center gap-2 mb-2">
                    <h3 className="text-sm font-semibold flex items-center gap-2">
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      {t('PendingChangesDrawer.sections.applying.heading')}
                      <Badge variant="default">{applying.length}</Badge>
                    </h3>
                  </header>
                  <ul className="space-y-2">
                    {applying.map((c) => renderChange(c, 'applying'))}
                  </ul>
                </section>
              )}

              {/* Failed */}
              {failed.length > 0 && (
                <section aria-label={t('PendingChangesDrawer.sections.failed.aria')}>
                  <header
                    className="flex items-center gap-1 mb-2 cursor-pointer select-none"
                    onClick={() => setFailedOpen((v) => !v)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setFailedOpen((v) => !v);
                      }
                    }}
                  >
                    {failedOpen ? (
                      <ChevronDown className="h-3.5 w-3.5" />
                    ) : (
                      <ChevronRight className="h-3.5 w-3.5" />
                    )}
                    <h3 className="text-sm font-semibold flex items-center gap-2 text-destructive">
                      <XCircle className="h-4 w-4" />
                      {t('PendingChangesDrawer.sections.failed.heading')}
                      <Badge variant="destructive">{failed.length}</Badge>
                    </h3>
                  </header>
                  {failedOpen && (
                    <ul className="space-y-2">
                      {failed.map((c) => renderChange(c, 'failed'))}
                    </ul>
                  )}
                </section>
              )}

              {/* Recently applied (collapsed by default) */}
              {applied.length > 0 && (
                <section aria-label={t('PendingChangesDrawer.sections.recentlyApplied.aria')}>
                  <header
                    className="flex items-center gap-1 mb-2 cursor-pointer select-none"
                    onClick={() => setAppliedOpen((v) => !v)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setAppliedOpen((v) => !v);
                      }
                    }}
                  >
                    {appliedOpen ? (
                      <ChevronDown className="h-3.5 w-3.5" />
                    ) : (
                      <ChevronRight className="h-3.5 w-3.5" />
                    )}
                    <h3 className="text-sm font-semibold flex items-center gap-2">
                      <CheckCircle2 className="h-4 w-4 text-green-600" />
                      {t('PendingChangesDrawer.sections.recentlyApplied.heading')}
                      <Badge variant="success">{applied.length}</Badge>
                    </h3>
                  </header>
                  {appliedOpen && (
                    <ul className="space-y-2">
                      {applied.map((c) => renderChange(c, 'applied'))}
                    </ul>
                  )}
                </section>
              )}
            </>
          )}
        </div>
      </SheetContent>

      {/* ── Per-row apply confirmation ───────────────────────────────── */}
      <AlertDialog
        open={confirmTarget !== null}
        onOpenChange={(o) => {
          if (!o) {
            setConfirmTarget(null);
            setConfirmText('');
          }
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              {confirmRequiresTyped && (
                <AlertTriangle className="h-4 w-4 text-destructive" />
              )}
              {t('PendingChangesDrawer.confirmApply.title')}
            </AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="space-y-2">
                <p>
                  {t('PendingChangesDrawer.confirmApply.bodyBefore')}{' '}
                  <span className="font-medium">{gatewayName}</span>
                  {t('PendingChangesDrawer.confirmApply.bodyAfter')}
                </p>
                {confirmTarget && (
                  <div className="rounded border border-border p-2 bg-muted">
                    <div className="flex items-center gap-2 mb-1">
                      <OperationBadge operation={confirmTarget.operation} />
                      <code className="text-xs font-mono">
                        {confirmTarget.feature}
                      </code>
                    </div>
                    {confirmTarget.target_id && (
                      <p className="text-xs text-muted-foreground">
                        {t('PendingChangesDrawer.change.targetLabel')}{' '}
                        <code className="font-mono">
                          {confirmTarget.target_id}
                        </code>
                      </p>
                    )}
                  </div>
                )}
                {confirmRequiresTyped && (
                  <div className="space-y-1">
                    <Label htmlFor="apply-confirm-text">
                      {t('PendingChangesDrawer.confirmApply.typedBefore')}{' '}
                      <code className="font-mono">APPLY</code>
                      {t('PendingChangesDrawer.confirmApply.typedAfter')}
                    </Label>
                    <Input
                      id="apply-confirm-text"
                      autoComplete="off"
                      spellCheck={false}
                      value={confirmText}
                      onChange={(e) => setConfirmText(e.target.value)}
                      placeholder="APPLY"
                    />
                  </div>
                )}
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel
              onClick={() => {
                setConfirmTarget(null);
                setConfirmText('');
              }}
            >
              {t('PendingChangesDrawer.actions.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              disabled={!confirmReady || applyMutation.isPending}
              onClick={() => {
                if (confirmTarget && confirmReady) {
                  applyMutation.mutate(confirmTarget);
                }
              }}
            >
              {applyMutation.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" />
              ) : null}
              {t('PendingChangesDrawer.actions.apply')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ── Discard confirmation ─────────────────────────────────────── */}
      <AlertDialog
        open={discardTarget !== null}
        onOpenChange={(o) => {
          if (!o) setDiscardTarget(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('PendingChangesDrawer.confirmDiscard.title')}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('PendingChangesDrawer.confirmDiscard.body')}{' '}
              {discardTarget && (
                <code className="font-mono text-xs block mt-2">
                  {discardTarget.feature}
                </code>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setDiscardTarget(null)}>
              {t('PendingChangesDrawer.actions.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (discardTarget) discardMutation.mutate(discardTarget.id);
              }}
              disabled={discardMutation.isPending}
            >
              {discardMutation.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" />
              ) : null}
              {t('PendingChangesDrawer.actions.discard')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ── Bulk-apply confirmation ─────────────────────────────────── */}
      <AlertDialog
        open={bulkOpen}
        onOpenChange={(o) => {
          if (!o && !bulkProgress) {
            setBulkOpen(false);
            setBulkConfirmText('');
          }
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-destructive" />
              {t('PendingChangesDrawer.bulkApply.title')}
            </AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="space-y-2">
                <p>
                  {t('PendingChangesDrawer.bulkApply.bodyBefore', {
                    count: pending.length,
                  })}{' '}
                  <span className="font-medium">{gatewayName}</span>
                  {t('PendingChangesDrawer.bulkApply.bodyAfter')}
                </p>
                <ul
                  className="max-h-40 overflow-y-auto rounded border border-border bg-muted p-2 space-y-1 text-xs"
                  aria-label={t('PendingChangesDrawer.bulkApply.summaryAria')}
                >
                  {pending.map((c) => (
                    <li key={c.id} className="flex items-center gap-2">
                      <OperationBadge operation={c.operation} />
                      <code className="font-mono truncate">{c.feature}</code>
                    </li>
                  ))}
                </ul>
                {bulkProgress ? (
                  <div className="rounded border border-border p-2 bg-muted text-xs">
                    {bulkProgress.error ? (
                      <p className="text-destructive">
                        {t('PendingChangesDrawer.bulkApply.stopped', {
                          current: bulkProgress.current,
                          total: bulkProgress.total,
                          error: bulkProgress.error,
                        })}
                      </p>
                    ) : (
                      <p>
                        {t('PendingChangesDrawer.bulkApply.progress', {
                          current: bulkProgress.current,
                          total: bulkProgress.total,
                        })}
                      </p>
                    )}
                  </div>
                ) : (
                  <div className="space-y-1">
                    <Label htmlFor="bulk-apply-confirm-text">
                      {t('PendingChangesDrawer.bulkApply.typedBefore')}{' '}
                      <code className="font-mono">APPLY ALL</code>
                      {t('PendingChangesDrawer.bulkApply.typedAfter')}
                    </Label>
                    <Input
                      id="bulk-apply-confirm-text"
                      autoComplete="off"
                      spellCheck={false}
                      value={bulkConfirmText}
                      onChange={(e) => setBulkConfirmText(e.target.value)}
                      placeholder="APPLY ALL"
                    />
                  </div>
                )}
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel
              onClick={() => {
                if (bulkProgress?.error) {
                  // After an error, "Close" exits and leaves the rest pending.
                  setBulkOpen(false);
                  setBulkProgress(null);
                  setBulkConfirmText('');
                } else if (!bulkProgress) {
                  setBulkOpen(false);
                  setBulkConfirmText('');
                }
              }}
              disabled={!!bulkProgress && !bulkProgress.error}
            >
              {bulkProgress?.error
                ? t('PendingChangesDrawer.actions.close')
                : t('PendingChangesDrawer.actions.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              disabled={
                bulkConfirmText !== 'APPLY ALL' ||
                !!bulkProgress ||
                pending.length === 0
              }
              onClick={(e) => {
                e.preventDefault();
                void runBulkApply();
              }}
            >
              {bulkProgress && !bulkProgress.error ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" />
              ) : null}
              {t('PendingChangesDrawer.bulkApply.applyCount', {
                count: pending.length,
              })}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Sheet>
  );
}

// ── Small helpers ──────────────────────────────────────────────────────

function OperationBadge({
  operation,
}: {
  operation: PendingChangeResponse['operation'];
}) {
  const { t } = useTranslation('common');
  switch (operation) {
    case 'create':
      return (
        <Badge variant="success">
          {t('PendingChangesDrawer.operations.create')}
        </Badge>
      );
    case 'update':
      return (
        <Badge variant="default">
          {t('PendingChangesDrawer.operations.update')}
        </Badge>
      );
    case 'delete':
      return (
        <Badge variant="destructive">
          {t('PendingChangesDrawer.operations.delete')}
        </Badge>
      );
  }
}
