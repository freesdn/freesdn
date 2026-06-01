// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * DiagnosticsTab · cable test, ping, traceroute panel for the switch detail view.
 *
 * Extracted from SwitchesPage as part of the monolith breakup. Owns its own
 * UI-local state (target inputs, current result, loading) and calls
 * switchesApi directly. The parent passes the switch id + total port count
 * and a toast handle.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { switchesApi } from '@/lib/api';

const isValidDiagTarget = (v: string): boolean => {
  if (!v.trim()) return false;
  // IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return true;
  // IPv6 (simplified check)
  if (/^[0-9a-fA-F:]+$/.test(v) && v.includes(':')) return true;
  // Hostname
  if (/^(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*$/.test(v)) return true;
  return false;
};

export interface DiagnosticsTabProps {
  selectedSwitchId: string | undefined;
  totalPorts: number | undefined;
  toast: (opts: { title: string; description?: string; variant?: 'default' | 'destructive' }) => void;
}

export function DiagnosticsTab({ selectedSwitchId, totalPorts, toast }: DiagnosticsTabProps) {
  const { t } = useTranslation('switches');
  const [pingTarget, setPingTarget] = useState('');
  const [tracerouteTarget, setTracerouteTarget] = useState('');
  const [diagPort, setDiagPort] = useState(1);
  const [diagResult, setDiagResult] = useState<Record<string, unknown> | null>(null);
  const [diagLoading, setDiagLoading] = useState(false);

  return (
    <>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Cable Test */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">{t('DiagnosticsTab.cableTest.title')}</CardTitle>
            <CardDescription>{t('DiagnosticsTab.cableTest.description')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-2">
              <Label className="text-xs">{t('DiagnosticsTab.cableTest.portNumber')}</Label>
              <Input
                type="number"
                min={1}
                max={totalPorts || 48}
                value={diagPort}
                onChange={(e) => setDiagPort(Number(e.target.value))}
              />
            </div>
            <Button
              className="w-full"
              size="sm"
              disabled={diagLoading}
              onClick={async () => {
                if (!selectedSwitchId) return;
                setDiagLoading(true);
                setDiagResult(null);
                try {
                  const r = await switchesApi.runCableTest(selectedSwitchId, diagPort);
                  setDiagResult(r.data as unknown as Record<string, unknown>);
                  toast({ title: t('DiagnosticsTab.cableTest.toastComplete') });
                } catch {
                  toast({ title: t('DiagnosticsTab.cableTest.toastFailed'), variant: 'destructive' });
                }
                setDiagLoading(false);
              }}
            >
              {diagLoading ? t('DiagnosticsTab.cableTest.running') : t('DiagnosticsTab.cableTest.run')}
            </Button>
          </CardContent>
        </Card>

        {/* Ping Test */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">{t('DiagnosticsTab.ping.title')}</CardTitle>
            <CardDescription>{t('DiagnosticsTab.ping.description')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-2">
              <Label className="text-xs">{t('DiagnosticsTab.targetLabel')}</Label>
              <Input
                placeholder={t('DiagnosticsTab.ping.placeholder')}
                value={pingTarget}
                onChange={(e) => setPingTarget(e.target.value)}
              />
            </div>
            <Button
              className="w-full"
              size="sm"
              disabled={diagLoading || !pingTarget || !isValidDiagTarget(pingTarget)}
              onClick={async () => {
                if (!selectedSwitchId || !pingTarget) return;
                setDiagLoading(true);
                setDiagResult(null);
                try {
                  const r = await switchesApi.runPing(selectedSwitchId, pingTarget);
                  setDiagResult(r.data as unknown as Record<string, unknown>);
                  toast({ title: t('DiagnosticsTab.ping.toastComplete') });
                } catch {
                  toast({ title: t('DiagnosticsTab.ping.toastFailed'), variant: 'destructive' });
                }
                setDiagLoading(false);
              }}
            >
              {diagLoading ? t('DiagnosticsTab.ping.running') : t('DiagnosticsTab.ping.run')}
            </Button>
          </CardContent>
        </Card>

        {/* Traceroute */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">{t('DiagnosticsTab.traceroute.title')}</CardTitle>
            <CardDescription>{t('DiagnosticsTab.traceroute.description')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-2">
              <Label className="text-xs">{t('DiagnosticsTab.targetLabel')}</Label>
              <Input
                placeholder={t('DiagnosticsTab.traceroute.placeholder')}
                value={tracerouteTarget}
                onChange={(e) => setTracerouteTarget(e.target.value)}
              />
            </div>
            <Button
              className="w-full"
              size="sm"
              disabled={diagLoading || !tracerouteTarget || !isValidDiagTarget(tracerouteTarget)}
              onClick={async () => {
                if (!selectedSwitchId || !tracerouteTarget) return;
                setDiagLoading(true);
                setDiagResult(null);
                try {
                  const r = await switchesApi.runTraceroute(selectedSwitchId, tracerouteTarget);
                  setDiagResult(r.data as unknown as Record<string, unknown>);
                  toast({ title: t('DiagnosticsTab.traceroute.toastComplete') });
                } catch {
                  toast({ title: t('DiagnosticsTab.traceroute.toastFailed'), variant: 'destructive' });
                }
                setDiagLoading(false);
              }}
            >
              {diagLoading ? t('DiagnosticsTab.traceroute.running') : t('DiagnosticsTab.traceroute.run')}
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Results */}
      {diagResult && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">{t('DiagnosticsTab.results.title')}</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="bg-muted rounded-lg p-4 text-xs font-mono overflow-x-auto max-h-[400px] overflow-y-auto whitespace-pre-wrap">
              {JSON.stringify(diagResult, null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}
    </>
  );
}
