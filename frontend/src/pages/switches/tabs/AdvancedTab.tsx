// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * AdvancedTab · OUI-based VLAN assignment + CLI configuration profile
 * for the switch detail view.
 *
 * Extracted from SwitchesPage as part of the monolith breakup. Owns its own
 * UI-local state (OUI mappings, CLI profile inputs, in-flight + result blobs)
 * and calls switchesApi directly. The parent passes the switch id and a
 * toast handle.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Plus, Trash2 } from 'lucide-react';
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
import { Textarea } from '@/components/ui/textarea';
import { switchesApi } from '@/lib/api';

const isValidOuiPrefix = (v: string): boolean =>
  /^[0-9A-Fa-f]{2}([:\-]?[0-9A-Fa-f]{2}){2}$/.test(v); // eslint-disable-line no-useless-escape

export interface AdvancedTabProps {
  selectedSwitchId: string | undefined;
  toast: (opts: { title: string; description?: string; variant?: 'default' | 'destructive' }) => void;
}

export function AdvancedTab({ selectedSwitchId, toast }: AdvancedTabProps) {
  const { t } = useTranslation('switches');

  // OUI VLAN state
  const [ouiMappings, setOuiMappings] = useState<Array<{ oui: string; vlan: number; desc: string }>>([
    { oui: '', vlan: 1, desc: '' },
  ]);
  const [ouiResult, setOuiResult] = useState<Record<string, unknown> | null>(null);
  const [ouiLoading, setOuiLoading] = useState(false);

  // CLI Profile state
  const [cliProfileName, setCliProfileName] = useState('');
  const [cliPortRange, setCliPortRange] = useState('');
  const [cliConfig, setCliConfig] = useState('{\n  "spanningTreeEnable": true,\n  "lldpMedEnable": true\n}');
  const [cliResult, setCliResult] = useState<Record<string, unknown> | null>(null);
  const [cliLoading, setCliLoading] = useState(false);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {/* OUI VLAN Assignment */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">{t('AdvancedTab.oui.title')}</CardTitle>
          <CardDescription>{t('AdvancedTab.oui.description')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {ouiMappings.map((m, i) => (
            <div key={i} className="flex gap-2 items-end">
              <div className="flex-1 space-y-1">
                <Label className="text-xs">{t('AdvancedTab.oui.prefixLabel')}</Label>
                <Input
                  placeholder="AA:BB:CC"
                  value={m.oui}
                  onChange={(e) => {
                    const updated = [...ouiMappings];
                    updated[i] = { ...m, oui: e.target.value };
                    setOuiMappings(updated);
                  }}
                />
              </div>
              <div className="w-20 space-y-1">
                <Label className="text-xs">{t('AdvancedTab.oui.vlanLabel')}</Label>
                <Input
                  type="number"
                  min={1}
                  max={4094}
                  value={m.vlan}
                  onChange={(e) => {
                    const updated = [...ouiMappings];
                    updated[i] = { ...m, vlan: Number(e.target.value) };
                    setOuiMappings(updated);
                  }}
                />
              </div>
              <div className="flex-1 space-y-1">
                <Label className="text-xs">{t('AdvancedTab.oui.descriptionLabel')}</Label>
                <Input
                  placeholder={t('AdvancedTab.oui.descriptionPlaceholder')}
                  value={m.desc}
                  onChange={(e) => {
                    const updated = [...ouiMappings];
                    updated[i] = { ...m, desc: e.target.value };
                    setOuiMappings(updated);
                  }}
                />
              </div>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setOuiMappings(ouiMappings.filter((_, j) => j !== i))}
                disabled={ouiMappings.length <= 1}
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            </div>
          ))}
          <Button
            variant="outline"
            size="sm"
            onClick={() => setOuiMappings([...ouiMappings, { oui: '', vlan: 1, desc: '' }])}
          >
            <Plus className="mr-2 h-4 w-4" />
            {t('AdvancedTab.oui.addMapping')}
          </Button>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              disabled={ouiLoading || !ouiMappings.some(m => m.oui && isValidOuiPrefix(m.oui))}
              onClick={async () => {
                if (!selectedSwitchId) return;
                setOuiLoading(true);
                try {
                  const r = await switchesApi.applyOuiVlan(selectedSwitchId, {
                    mappings: ouiMappings.filter(m => m.oui && isValidOuiPrefix(m.oui)).map(m => ({
                      oui_prefix: m.oui, vlan_id: m.vlan, description: m.desc || undefined,
                    })),
                    dry_run: true,
                  });
                  setOuiResult(r.data as unknown as Record<string, unknown>);
                  toast({ title: t('AdvancedTab.oui.previewToast', { count: (r.data as { changes?: unknown[] })?.changes?.length || 0 }) });
                } catch { toast({ title: t('AdvancedTab.oui.previewFailed'), variant: 'destructive' }); }
                setOuiLoading(false);
              }}
            >
              {t('AdvancedTab.oui.preview')}
            </Button>
            <Button
              size="sm"
              disabled={ouiLoading || !ouiMappings.some(m => m.oui && isValidOuiPrefix(m.oui))}
              onClick={async () => {
                if (!selectedSwitchId) return;
                setOuiLoading(true);
                try {
                  const r = await switchesApi.applyOuiVlan(selectedSwitchId, {
                    mappings: ouiMappings.filter(m => m.oui && isValidOuiPrefix(m.oui)).map(m => ({
                      oui_prefix: m.oui, vlan_id: m.vlan, description: m.desc || undefined,
                    })),
                    dry_run: false,
                  });
                  setOuiResult(r.data as unknown as Record<string, unknown>);
                  toast({ title: t('AdvancedTab.oui.appliedToast', { count: (r.data as { applied?: number })?.applied || 0 }) });
                } catch { toast({ title: t('AdvancedTab.oui.applyFailed'), variant: 'destructive' }); }
                setOuiLoading(false);
              }}
            >
              {ouiLoading ? t('AdvancedTab.common.applying') : t('AdvancedTab.common.apply')}
            </Button>
          </div>
          {ouiResult && (
            <pre className="bg-muted rounded p-3 text-xs font-mono overflow-x-auto max-h-[200px] overflow-y-auto whitespace-pre-wrap">
              {JSON.stringify(ouiResult, null, 2)}
            </pre>
          )}
        </CardContent>
      </Card>

      {/* CLI Profile */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">{t('AdvancedTab.cli.title')}</CardTitle>
          <CardDescription>{t('AdvancedTab.cli.description')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-2">
            <Label className="text-xs">{t('AdvancedTab.cli.profileNameLabel')}</Label>
            <Input
              placeholder={t('AdvancedTab.cli.profileNamePlaceholder')}
              value={cliProfileName}
              onChange={(e) => setCliProfileName(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label className="text-xs">{t('AdvancedTab.cli.portRangeLabel')}</Label>
            <Input
              placeholder="e.g. 1,2,3,4,5"
              value={cliPortRange}
              onChange={(e) => setCliPortRange(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label className="text-xs">{t('AdvancedTab.cli.configLabel')}</Label>
            <Textarea
              className="font-mono text-xs"
              rows={6}
              value={cliConfig}
              onChange={(e) => setCliConfig(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              {t('AdvancedTab.cli.keysHint', { keys: 'spanningTreeEnable, lldpMedEnable, portIsolationEnable, loopbackDetectEnable, flowControlEnable' })}
            </p>
          </div>
          <Button
            size="sm"
            className="w-full"
            disabled={cliLoading || !cliProfileName || !cliPortRange}
            onClick={async () => {
              if (!selectedSwitchId) return;
              setCliLoading(true);
              setCliResult(null);
              try {
                const ports = cliPortRange.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
                const config = JSON.parse(cliConfig);
                const r = await switchesApi.applyCLIProfile(selectedSwitchId, {
                  name: cliProfileName,
                  port_indices: ports,
                  config,
                });
                setCliResult(r.data as unknown as Record<string, unknown>);
                toast({ title: t('AdvancedTab.cli.appliedToast', { succeeded: (r.data as { succeeded?: number })?.succeeded || 0, total: ports.length }) });
              } catch (e) {
                toast({ title: e instanceof SyntaxError ? t('AdvancedTab.cli.invalidJson') : t('AdvancedTab.cli.applyFailed'), variant: 'destructive' });
              }
              setCliLoading(false);
            }}
          >
            {cliLoading ? t('AdvancedTab.common.applying') : t('AdvancedTab.cli.applyProfile')}
          </Button>
          {cliResult && (
            <pre className="bg-muted rounded p-3 text-xs font-mono overflow-x-auto max-h-[200px] overflow-y-auto whitespace-pre-wrap">
              {JSON.stringify(cliResult, null, 2)}
            </pre>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
