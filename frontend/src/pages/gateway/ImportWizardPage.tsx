// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Gateway Import Wizard
 *
 * 6-step brownfield import flow:
 *   1. Start / Discover  (automatic · creates session, discovers devices)
 *   2. Assign Roles       (user picks brain vs limb for each device)
 *   3. Scan               (automatic · pulls VLANs, interfaces, DHCP, DNS)
 *   4. Reconcile          (user reviews conflicts and decides per-resource)
 *   5. Apply              (automatic · creates canonical VLANs, distributes)
 *   6. Verify             (automatic · re-scans and confirms)
 *
 * Two user-input gates: step 2 and step 4.
 * One POST /start kicks off step 1→2; POST /step at step 2 runs 2+3;
 * POST /step at step 4 runs 4+5+6.
 */

import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  Router,
  Search,
  UserCheck,
  Scan,
  Scale,
  Rocket,
  CheckCircle2,
  ArrowLeft,
  ArrowRight,
  XCircle,
  Loader2,
  AlertTriangle,

  Brain,
  Cpu,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from '@/components/ui/card';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { cn } from '@/lib/utils';
import { PageHeader } from '@/components/layout';
import {
  gatewayOrchApi,
  sitesApiV2,
  type ImportSessionResponse,
  type Site,
} from '@/lib/api';

// =============================================================================
// Constants
// =============================================================================

const WIZARD_STEPS = [
  { num: 1, labelKey: 'discover', icon: Search, descriptionKey: 'discover' },
  { num: 2, labelKey: 'assignRoles', icon: UserCheck, descriptionKey: 'assignRoles' },
  { num: 3, labelKey: 'scan', icon: Scan, descriptionKey: 'scan' },
  { num: 4, labelKey: 'reconcile', icon: Scale, descriptionKey: 'reconcile' },
  { num: 5, labelKey: 'apply', icon: Rocket, descriptionKey: 'apply' },
  { num: 6, labelKey: 'verify', icon: CheckCircle2, descriptionKey: 'verify' },
] as const;

type RoleAssignment = Record<string, 'brain' | 'limb'>;
type ReconcileDecision = Record<string, 'import' | 'adopt_brain' | 'adopt_limb' | 'keep_both' | 'ignore'>;

interface DiscoveredDevice {
  name: string;
  vendor: string;
  host: string;
  is_online: boolean;
  capabilities: string[];
  detected_version: string;
}

// =============================================================================
// Page
// =============================================================================

export default function ImportWizardPage() {
  const { t } = useTranslation('gateway');
  const { sessionId } = useParams<{ sessionId?: string }>();
  const navigate = useNavigate();

  // Selected site for starting a new import
  const [selectedSiteId, setSelectedSiteId] = useState('');
  // Role assignments (step 2 user input)
  const [roles, setRoles] = useState<RoleAssignment>({});
  // Reconcile decisions (step 4 user input)
  const [decisions, setDecisions] = useState<ReconcileDecision>({});
  // Processing state for auto-steps
  const [isProcessing, setIsProcessing] = useState(false);
  // Cancel confirm dialog
  const [showCancelDialog, setShowCancelDialog] = useState(false);

  // ── Sites ────────────────────────────────────────────────────────────
  const { data: sitesData } = useQuery({
    queryKey: ['sites'],
    queryFn: async () => {
      const response = await sitesApiV2.list();
      return response.data;
    },
  });
  const sites: Site[] = sitesData?.items ?? [];

  // ── Session ──────────────────────────────────────────────────────────
  const {
    data: sessionRes,
    isLoading: sessionLoading,
    refetch: refetchSession,
  } = useQuery({
    queryKey: ['gateway', 'import', sessionId],
    queryFn: () => gatewayOrchApi.getImportSession(sessionId!),
    enabled: !!sessionId,
    refetchInterval: (query) => {
      // Poll during auto-processing steps
      const s = query.state.data?.data;
      if (s && (s.current_step === 3 || s.current_step === 5)) return 2000;
      return false;
    },
  });
  const session: ImportSessionResponse | null = sessionRes?.data ?? null;

  // Derive current step
  const currentStep = session?.current_step ?? 1;
  const isComplete = session?.status === 'completed';
  const isFailed = session?.status === 'failed';
  const isCancelled = session?.status === 'cancelled';

  // Pre-populate roles from session when we navigate to an existing session at step 2
  useEffect(() => {
    if (session && currentStep >= 2 && Object.keys(roles).length === 0) {
      const discovered = session.discovered_devices as Record<string, DiscoveredDevice>;
      if (Object.keys(discovered).length > 0 && Object.keys(session.role_assignments).length === 0) {
        // Default first device to brain, rest to limb
        const ids = Object.keys(discovered);
        const defaults: RoleAssignment = {};
        ids.forEach((id, idx) => {
          defaults[id] = idx === 0 ? 'brain' : 'limb';
        });
        setRoles(defaults);
      } else if (Object.keys(session.role_assignments).length > 0) {
        // Session already has roles - show as-is
        const existing = session.role_assignments as Record<string, string>;
        const r: RoleAssignment = {};
        for (const [k, v] of Object.entries(existing)) {
          r[k] = v as 'brain' | 'limb';
        }
        setRoles(r);
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps -- roles excluded to avoid re-initialization fighting with user input
  }, [session, currentStep]);

  // Pre-populate reconcile decisions at step 4
  useEffect(() => {
    if (session && currentStep >= 4 && Object.keys(decisions).length === 0) {
      const existing = session.reconciliation_decisions as Record<string, string> | undefined;
      if (existing && Object.keys(existing).length > 0) {
        const d: ReconcileDecision = {};
        for (const [k, v] of Object.entries(existing)) {
          d[k] = v as ReconcileDecision[string];
        }
        setDecisions(d);
      } else {
        // Auto-default everything to "import"
        const scan = (session.scan_results ?? {}) as Record<string, unknown>;
        const brainVlans = (scan.brain_vlans ?? []) as Array<{ tag: number }>;
        const d: ReconcileDecision = {};
        brainVlans.forEach((v) => { d[`vlan:${v.tag}`] = 'import'; });
        setDecisions(d);
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps -- decisions excluded to avoid re-initialization fighting with user input
  }, [session, currentStep]);

  // ── Start Import ─────────────────────────────────────────────────────
  const startMutation = useMutation({
    mutationFn: (data: { site_id: string; organization_id: string }) =>
      gatewayOrchApi.startImport(data),
    onSuccess: (res) => {
      const newSession = res.data;
      navigate(`/firewall/orchestration/import/${newSession.id}`, { replace: true });
    },
  });

  // ── Advance Step ─────────────────────────────────────────────────────
  const advanceMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      gatewayOrchApi.advanceImport(id, { payload }),
    onSuccess: () => {
      refetchSession();
      setIsProcessing(false);
    },
    onError: () => {
      setIsProcessing(false);
    },
  });

  // ── Cancel ───────────────────────────────────────────────────────────
  const cancelMutation = useMutation({
    mutationFn: (id: string) => gatewayOrchApi.cancelImport(id),
    onSuccess: () => {
      setShowCancelDialog(false);
      navigate('/firewall/orchestration');
    },
  });

  // ── Handlers ─────────────────────────────────────────────────────────
  const handleStart = () => {
    if (!selectedSiteId) return;
    // organization_id is injected server-side from the auth context
    startMutation.mutate({ site_id: selectedSiteId, organization_id: '' });
  };

  const handleSubmitRoles = () => {
    if (!session) return;
    setIsProcessing(true);
    advanceMutation.mutate({
      id: session.id,
      payload: { roles },
    });
  };

  const handleSubmitReconciliation = () => {
    if (!session) return;
    setIsProcessing(true);
    advanceMutation.mutate({
      id: session.id,
      payload: { decisions },
    });
  };

  // =============================================================================
  // Render: Step Indicator
  // =============================================================================

  function renderStepIndicator() {
    return (
      <div className="flex items-center justify-between mb-8">
        {WIZARD_STEPS.map((step, idx) => {
          const isActive = currentStep === step.num;
          const isDone = currentStep > step.num || isComplete;
          const StepIcon = step.icon;

          return (
            <div key={step.num} className="flex items-center flex-1 last:flex-initial">
              {/* Step circle */}
              <div className="flex flex-col items-center">
                <div
                  className={cn(
                    'w-10 h-10 rounded-full flex items-center justify-center border-2 transition-colors',
                    isDone
                      ? 'bg-green-500/20 border-green-500 text-green-500'
                      : isActive
                        ? 'bg-primary/10 border-primary text-primary'
                        : 'border-muted-foreground/30 text-muted-foreground/50',
                  )}
                >
                  {isDone ? (
                    <CheckCircle2 className="h-5 w-5" />
                  ) : (
                    <StepIcon className="h-4 w-4" />
                  )}
                </div>
                <span
                  className={cn(
                    'text-xs mt-1.5 font-medium text-center',
                    isActive ? 'text-primary' : isDone ? 'text-green-500' : 'text-muted-foreground/50',
                  )}
                >
                  {t(`ImportWizardPage.steps.${step.labelKey}.label`)}
                </span>
              </div>
              {/* Connector line */}
              {idx < WIZARD_STEPS.length - 1 && (
                <div
                  className={cn(
                    'flex-1 h-0.5 mx-2 mt-[-16px]',
                    currentStep > step.num ? 'bg-green-500' : 'bg-muted-foreground/20',
                  )}
                />
              )}
            </div>
          );
        })}
      </div>
    );
  }

  // =============================================================================
  // Render: No Session (Site Selection)
  // =============================================================================

  function renderSiteSelection() {
    return (
      <Card className="max-w-lg mx-auto">
        <CardHeader className="text-center">
          <CardTitle>{t('ImportWizardPage.siteSelection.title')}</CardTitle>
          <CardDescription>
            {t('ImportWizardPage.siteSelection.description')}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-2">
            <Label>{t('ImportWizardPage.siteSelection.selectSite')}</Label>
            <Select value={selectedSiteId} onValueChange={setSelectedSiteId}>
              <SelectTrigger>
                <SelectValue placeholder={t('ImportWizardPage.siteSelection.sitePlaceholder')} />
              </SelectTrigger>
              <SelectContent>
                {sites.map((s) => (
                  <SelectItem key={s.id} value={s.id}>{s.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <Button
            className="w-full"
            disabled={!selectedSiteId || startMutation.isPending}
            onClick={handleStart}
          >
            {startMutation.isPending ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                {t('ImportWizardPage.siteSelection.discovering')}
              </>
            ) : (
              <>
                <Search className="h-4 w-4 mr-2" />
                {t('ImportWizardPage.siteSelection.startImport')}
              </>
            )}
          </Button>

          {startMutation.isError && (
            <p className="text-sm text-destructive text-center">
              {t('ImportWizardPage.siteSelection.startError')}
            </p>
          )}
        </CardContent>
      </Card>
    );
  }

  // =============================================================================
  // Render: Step 2 · Assign Roles
  // =============================================================================

  function renderAssignRoles() {
    if (!session) return null;
    const discovered = session.discovered_devices as Record<string, DiscoveredDevice>;
    const deviceIds = Object.keys(discovered);

    if (deviceIds.length === 0) {
      return (
        <Card>
          <CardContent noOffset className="py-12 text-center">
            <AlertTriangle className="h-10 w-10 mx-auto text-yellow-500 mb-3" />
            <p className="text-lg font-medium">{t('ImportWizardPage.assignRoles.noDevicesTitle')}</p>
            <p className="text-sm text-muted-foreground mt-1">
              {t('ImportWizardPage.assignRoles.noDevicesDescription')}
            </p>
            <Button className="mt-4" variant="outline" asChild>
              <Link to="/firewall/orchestration">{t('ImportWizardPage.actions.backToGateway')}</Link>
            </Button>
          </CardContent>
        </Card>
      );
    }

    const hasBrain = Object.values(roles).some((r) => r === 'brain');

    return (
      <div className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>{t('ImportWizardPage.assignRoles.title')}</CardTitle>
            <CardDescription>
              {t('ImportWizardPage.assignRoles.descriptionBefore')}{' '}
              <strong>{t('ImportWizardPage.assignRoles.brain')}</strong>
              {t('ImportWizardPage.assignRoles.descriptionMiddle')}{' '}
              <strong>{t('ImportWizardPage.assignRoles.limbs')}</strong>
              {t('ImportWizardPage.assignRoles.descriptionAfter')}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {deviceIds.map((gwId) => {
              const dev = discovered[gwId];
              const role = roles[gwId] ?? 'limb';

              return (
                <div
                  key={gwId}
                  className={cn(
                    'flex items-center justify-between p-4 rounded-lg border transition-colors',
                    role === 'brain'
                      ? 'border-purple-500/40 bg-purple-500/5'
                      : 'border-border',
                  )}
                >
                  <div className="flex items-center gap-4">
                    <div className={cn(
                      'w-10 h-10 rounded-full flex items-center justify-center',
                      role === 'brain' ? 'bg-purple-500/20' : 'bg-muted',
                    )}>
                      {role === 'brain' ? (
                        <Brain className="h-5 w-5 text-purple-500" />
                      ) : (
                        <Cpu className="h-5 w-5 text-muted-foreground" />
                      )}
                    </div>
                    <div>
                      <p className="font-medium">{dev.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {dev.vendor} · {dev.host} · v{dev.detected_version}
                      </p>
                      <div className="flex items-center gap-2 mt-1">
                        <Badge variant="outline" className={cn(
                          dev.is_online ? 'bg-green-500/10 text-green-500' : 'bg-red-500/10 text-red-500',
                        )}>
                          {dev.is_online ? t('ImportWizardPage.assignRoles.online') : t('ImportWizardPage.assignRoles.offline')}
                        </Badge>
                        {dev.capabilities?.map((cap) => (
                          <Badge key={cap} variant="secondary" className="text-xs">
                            {cap}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>

                  <Select
                    value={role}
                    onValueChange={(v) => setRoles({ ...roles, [gwId]: v as 'brain' | 'limb' })}
                  >
                    <SelectTrigger className="w-32">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="brain">{t('ImportWizardPage.assignRoles.roleBrain')}</SelectItem>
                      <SelectItem value="limb">{t('ImportWizardPage.assignRoles.roleLimb')}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              );
            })}
          </CardContent>
        </Card>

        {!hasBrain && (
          <div className="flex items-center gap-2 text-sm text-yellow-500">
            <AlertTriangle className="h-4 w-4" />
            {t('ImportWizardPage.assignRoles.brainRequired')}
          </div>
        )}

        <div className="flex justify-end gap-3">
          <Button variant="outline" onClick={() => setShowCancelDialog(true)}>
            {t('ImportWizardPage.actions.cancel')}
          </Button>
          <Button
            onClick={handleSubmitRoles}
            disabled={!hasBrain || isProcessing || advanceMutation.isPending}
          >
            {isProcessing || advanceMutation.isPending ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                {t('ImportWizardPage.assignRoles.scanning')}
              </>
            ) : (
              <>
                <ArrowRight className="h-4 w-4 mr-2" />
                {t('ImportWizardPage.assignRoles.scanDevices')}
              </>
            )}
          </Button>
        </div>
      </div>
    );
  }

  // =============================================================================
  // Render: Step 3 · Scanning (auto)
  // =============================================================================

  function renderScanning() {
    return (
      <Card className="max-w-md mx-auto">
        <CardContent noOffset className="py-12 text-center">
          <Loader2 className="h-12 w-12 mx-auto animate-spin text-primary mb-4" />
          <p className="text-lg font-medium">{t('ImportWizardPage.scanning.title')}</p>
          <p className="text-sm text-muted-foreground mt-1">
            {t('ImportWizardPage.scanning.description')}
          </p>
        </CardContent>
      </Card>
    );
  }

  // =============================================================================
  // Render: Step 4 · Reconcile
  // =============================================================================

  function renderReconcile() {
    if (!session) return null;

    const scan = (session.scan_results ?? {}) as Record<string, unknown>;
    const conflicts = (session.conflicts ?? []) as Array<{
      type: string;
      vlan_tag: number;
      message: string;
    }>;

    // Extract discovered VLANs from scan_results
    const brainVlans = (scan.brain_vlans ?? []) as Array<{
      tag: number;
      description: string;
      subnet: string;
      gateway_ip: string;
    }>;

    return (
      <div className="space-y-4">
        {/* Conflicts */}
        {conflicts.length > 0 && (
          <Card className="border-yellow-500/30">
            <CardHeader>
              <CardTitle className="text-yellow-500 flex items-center gap-2">
                <AlertTriangle className="h-5 w-5" />
                {t('ImportWizardPage.reconcile.conflictsTitle', { count: conflicts.length })}
              </CardTitle>
              <CardDescription>
                {t('ImportWizardPage.reconcile.conflictsDescription')}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {conflicts.map((c, idx) => (
                  <div
                    key={idx}
                    className="flex items-start gap-3 p-3 rounded-lg bg-yellow-500/5 border border-yellow-500/20"
                  >
                    <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5 flex-shrink-0" />
                    <div>
                      <p className="text-sm font-medium">
                        {t('ImportWizardPage.reconcile.conflictItem', { type: c.type, tag: c.vlan_tag })}
                      </p>
                      <p className="text-xs text-muted-foreground">{c.message}</p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Discovered VLANs */}
        <Card>
          <CardHeader>
            <CardTitle>{t('ImportWizardPage.reconcile.discoveredVlansTitle')}</CardTitle>
            <CardDescription>
              {t('ImportWizardPage.reconcile.discoveredVlansDescription')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {brainVlans.length === 0 && (
                <p className="text-sm text-muted-foreground text-center py-4">
                  {t('ImportWizardPage.reconcile.noVlans')}
                </p>
              )}
              {brainVlans.map((vlan) => {
                const key = `vlan:${vlan.tag}`;
                const decision = decisions[key] ?? 'import';
                const hasConflict = conflicts.some((c) => c.vlan_tag === vlan.tag);

                return (
                  <div
                    key={vlan.tag}
                    className={cn(
                      'flex items-center justify-between p-3 rounded-lg border',
                      hasConflict ? 'border-yellow-500/30 bg-yellow-500/5' : 'border-border',
                    )}
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-12 h-8 rounded bg-muted flex items-center justify-center font-mono text-sm font-bold">
                        {vlan.tag}
                      </div>
                      <div>
                        <p className="text-sm font-medium">{vlan.description || t('ImportWizardPage.reconcile.vlanLabel', { tag: vlan.tag })}</p>
                        <p className="text-xs text-muted-foreground font-mono">
                          {vlan.subnet} → {vlan.gateway_ip}
                        </p>
                      </div>
                      {hasConflict && (
                        <Badge variant="outline" className="bg-yellow-500/10 text-yellow-500 text-xs">
                          {t('ImportWizardPage.reconcile.conflictBadge')}
                        </Badge>
                      )}
                    </div>

                    <Select
                      value={decision}
                      onValueChange={(v) => setDecisions({ ...decisions, [key]: v as ReconcileDecision[string] })}
                    >
                      <SelectTrigger className="w-40">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="import">{t('ImportWizardPage.reconcile.decisionImport')}</SelectItem>
                        <SelectItem value="adopt_brain">{t('ImportWizardPage.reconcile.decisionAdoptBrain')}</SelectItem>
                        <SelectItem value="adopt_limb">{t('ImportWizardPage.reconcile.decisionAdoptLimb')}</SelectItem>
                        <SelectItem value="keep_both">{t('ImportWizardPage.reconcile.decisionKeepBoth')}</SelectItem>
                        <SelectItem value="ignore">{t('ImportWizardPage.reconcile.decisionIgnore')}</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        <div className="flex justify-end gap-3">
          <Button variant="outline" onClick={() => setShowCancelDialog(true)}>
            {t('ImportWizardPage.actions.cancel')}
          </Button>
          <Button
            onClick={handleSubmitReconciliation}
            disabled={isProcessing || advanceMutation.isPending}
          >
            {isProcessing || advanceMutation.isPending ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                {t('ImportWizardPage.reconcile.applying')}
              </>
            ) : (
              <>
                <Rocket className="h-4 w-4 mr-2" />
                {t('ImportWizardPage.reconcile.applyVerify')}
              </>
            )}
          </Button>
        </div>
      </div>
    );
  }

  // =============================================================================
  // Render: Step 5 · Applying (auto)
  // =============================================================================

  function renderApplying() {
    return (
      <Card className="max-w-md mx-auto">
        <CardContent noOffset className="py-12 text-center">
          <Loader2 className="h-12 w-12 mx-auto animate-spin text-primary mb-4" />
          <p className="text-lg font-medium">{t('ImportWizardPage.applying.title')}</p>
          <p className="text-sm text-muted-foreground mt-1">
            {t('ImportWizardPage.applying.description')}
          </p>
        </CardContent>
      </Card>
    );
  }

  // =============================================================================
  // Render: Step 6 · Complete / Verification Report
  // =============================================================================

  function renderComplete() {
    if (!session) return null;

    const report = session.verification_report as {
      status?: string;
      timestamp?: string;
      mismatches?: Array<{ vlan_tag: number; issue: string }>;
    };
    const verified = report?.status === 'verified';
    const mismatches = report?.mismatches ?? [];

    return (
      <div className="space-y-4 max-w-2xl mx-auto">
        <Card className={cn(
          'border-2',
          verified ? 'border-green-500/30' : 'border-yellow-500/30',
        )}>
          <CardContent noOffset className="py-8 text-center">
            {verified ? (
              <>
                <CheckCircle2 className="h-14 w-14 mx-auto text-green-500 mb-4" />
                <p className="text-xl font-bold text-green-500">{t('ImportWizardPage.complete.verifiedTitle')}</p>
                <p className="text-sm text-muted-foreground mt-1">
                  {t('ImportWizardPage.complete.verifiedDescription')}
                </p>
              </>
            ) : (
              <>
                <AlertTriangle className="h-14 w-14 mx-auto text-yellow-500 mb-4" />
                <p className="text-xl font-bold text-yellow-500">{t('ImportWizardPage.complete.mismatchTitle')}</p>
                <p className="text-sm text-muted-foreground mt-1">
                  {t('ImportWizardPage.complete.mismatchDescription')}
                </p>
              </>
            )}
          </CardContent>
        </Card>

        {mismatches.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-yellow-500">{t('ImportWizardPage.complete.mismatchesTitle', { count: mismatches.length })}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {mismatches.map((m, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-3 p-3 rounded-lg bg-yellow-500/5 border border-yellow-500/20"
                >
                  <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="text-sm font-medium">{t('ImportWizardPage.reconcile.vlanLabel', { tag: m.vlan_tag })}</p>
                    <p className="text-xs text-muted-foreground">{m.issue}</p>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        )}

        {(session.distribution_ids ?? []).length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>{t('ImportWizardPage.complete.distributionRecordsTitle')}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                {t('ImportWizardPage.complete.distributionQueued', { count: (session.distribution_ids ?? []).length })}{' '}
                {t('ImportWizardPage.complete.distributionViewDetails')}{' '}
                <Link to="/firewall/orchestration/distribution" className="text-primary underline">
                  {t('ImportWizardPage.complete.distributionTab')}
                </Link>
                .
              </p>
            </CardContent>
          </Card>
        )}

        <div className="flex justify-center gap-3 pt-4">
          <Button variant="outline" asChild>
            <Link to="/firewall/orchestration">
              <ArrowLeft className="h-4 w-4 mr-2" />
              {t('ImportWizardPage.actions.backToGateway')}
            </Link>
          </Button>
          <Button variant="outline" asChild>
            <Link to="/firewall/orchestration/vlans">
              {t('ImportWizardPage.complete.viewCanonicalVlans')}
            </Link>
          </Button>
        </div>
      </div>
    );
  }

  // =============================================================================
  // Render: Failed / Cancelled
  // =============================================================================

  function renderFailed() {
    return (
      <Card className="max-w-md mx-auto border-red-500/30">
        <CardContent noOffset className="py-12 text-center">
          <XCircle className="h-14 w-14 mx-auto text-red-500 mb-4" />
          <p className="text-xl font-bold text-red-500">
            {isCancelled ? t('ImportWizardPage.failed.cancelledTitle') : t('ImportWizardPage.failed.failedTitle')}
          </p>
          <p className="text-sm text-muted-foreground mt-2">
            {isCancelled
              ? t('ImportWizardPage.failed.cancelledDescription')
              : t('ImportWizardPage.failed.failedDescription')}
          </p>
          <div className="flex justify-center gap-3 mt-6">
            <Button variant="outline" asChild>
              <Link to="/firewall/orchestration">
                <ArrowLeft className="h-4 w-4 mr-2" />
                {t('ImportWizardPage.actions.backToGateway')}
              </Link>
            </Button>
            <Button asChild>
              <Link to="/firewall/orchestration/import">
                {t('ImportWizardPage.failed.retry')}
              </Link>
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  // =============================================================================
  // Render: Step Content
  // =============================================================================

  function renderStepContent() {
    if (sessionLoading) {
      return (
        <div className="space-y-4">
          <Skeleton className="h-32 rounded-xl" />
          <Skeleton className="h-48 rounded-xl" />
        </div>
      );
    }

    if (isFailed || isCancelled) return renderFailed();
    if (isComplete || currentStep === 6) return renderComplete();

    switch (currentStep) {
      case 1:
      case 2:
        return renderAssignRoles();
      case 3:
        return renderScanning();
      case 4:
        return renderReconcile();
      case 5:
        return renderApplying();
      default:
        return renderAssignRoles();
    }
  }

  // =============================================================================
  // Layout
  // =============================================================================

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Router}
        title={t('ImportWizardPage.header.title')}
        subtitle={session
          ? t('ImportWizardPage.header.subtitleSession', { id: session.id.slice(0, 8), step: currentStep })
          : t('ImportWizardPage.header.subtitleDefault')}
        actions={
          session && !isComplete && !isFailed && !isCancelled ? (
            <Button
              variant="outline"
              size="sm"
              className="text-destructive"
              onClick={() => setShowCancelDialog(true)}
            >
              <XCircle className="h-4 w-4 mr-2" />
              {t('ImportWizardPage.actions.cancelImport')}
            </Button>
          ) : undefined
        }
      />

      {/* Show step indicator when we have a session */}
      {session && !isFailed && !isCancelled && renderStepIndicator()}

      {/* Content */}
      {!sessionId ? renderSiteSelection() : renderStepContent()}

      {/* Cancel Dialog */}
      <Dialog open={showCancelDialog} onOpenChange={setShowCancelDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('ImportWizardPage.cancelDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('ImportWizardPage.cancelDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCancelDialog(false)}>
              {t('ImportWizardPage.cancelDialog.continue')}
            </Button>
            <Button
              variant="destructive"
              onClick={() => session && cancelMutation.mutate(session.id)}
              disabled={cancelMutation.isPending}
            >
              {cancelMutation.isPending ? t('ImportWizardPage.cancelDialog.cancelling') : t('ImportWizardPage.actions.cancelImport')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
