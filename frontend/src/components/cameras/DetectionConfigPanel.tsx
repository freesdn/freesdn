// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, Detection Configuration Panel
 *
 * Tabbed configuration UI for Motion Detection, Line Crossing,
 * Intrusion Detection, and Privacy Masks.  Fetches smart-capabilities
 * first to decide which tabs are available.
 */

import { useState, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  camerasApi,
  type SmartCapabilities,
  type MotionDetectionConfig,
  type PrivacyMaskConfig,
  type PrivacyMaskRegion,
  type LineCrossingConfig,
  type LineCrossingRule,
  type IntrusionDetectionConfig,
  type IntrusionDetectionRule,
  type FaceDetectionConfig,
} from '@/lib/api';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Slider } from '@/components/ui/slider';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs';
import {
  Activity,
  ArrowLeftRight,
  ShieldAlert,
  EyeOff,
  ScanFace,
  Loader2,
  Save,
  CheckCircle2,
  XCircle,
  Ban,
  Pencil,
  Plus,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { isNativeVendor } from '@/lib/cameraVendors';
import { RegionEditDialog } from './RegionEditDialog';
import { VendorCapabilityNote } from './VendorCapabilityNote';
import {
  CameraCanvasOverlay,
  GridOverlay,
  RectangleOverlay,
  LineOverlay,
  PolygonOverlay,
} from './CameraCanvasOverlay';

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface DetectionConfigPanelProps {
  cameraId: string;
  /** Camera vendor, drives the native-support gate (zones require Hikvision today). */
  vendor?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Badge shown when a capability isn't supported by the camera. */
function NotSupportedBadge() {
  const { t } = useTranslation('common');
  return (
    <Badge variant="outline" className="text-muted-foreground gap-1">
      <Ban className="h-3 w-3" />
      {t('DetectionConfigPanel.notSupported')}
    </Badge>
  );
}

/** Inline status indicator after a save attempt. */
function SaveStatus({ status }: { status: 'idle' | 'saving' | 'success' | 'error' }) {
  if (status === 'saving')
    return <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />;
  if (status === 'success')
    return <CheckCircle2 className="h-4 w-4 text-emerald-500" />;
  if (status === 'error')
    return <XCircle className="h-4 w-4 text-destructive" />;
  return null;
}

// ---------------------------------------------------------------------------
// Sub-tab: Motion Detection
// ---------------------------------------------------------------------------

function MotionDetectionTab({ cameraId }: { cameraId: string }) {
  const { t } = useTranslation('common');
  const qc = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['camera', cameraId, 'motion-detection'],
    queryFn: () => camerasApi.getMotionDetection(cameraId).then((r) => r.data),
  });

  const [config, setConfig] = useState<MotionDetectionConfig | null>(null);
  useEffect(() => {
    if (data) setConfig({ ...data });
  }, [data]);

  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'success' | 'error'>('idle');

  const mutation = useMutation({
    mutationFn: (payload: MotionDetectionConfig) =>
      camerasApi.setMotionDetection(cameraId, payload),
    onMutate: () => setSaveStatus('saving'),
    onSuccess: () => {
      setSaveStatus('success');
      qc.invalidateQueries({ queryKey: ['camera', cameraId, 'motion-detection'] });
      setTimeout(() => setSaveStatus('idle'), 2000);
    },
    onError: (err) => {
      setSaveStatus('error');
      console.error('[DetectionConfig] Motion detection save failed', err);
      setTimeout(() => setSaveStatus('idle'), 3000);
    },
  });

  if (isLoading || !config)
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" /> {t('DetectionConfigPanel.loading')}
      </div>
    );

  return (
    <div className="space-y-6">
      {/* Canvas overlay for motion grid */}
      <CameraCanvasOverlay cameraId={cameraId} width={560} className="mx-auto">
        <GridOverlay
          gridMap={config.grid_map || ''}
          onChange={(newMap) => setConfig({ ...config, grid_map: newMap })}
          editable={config.enabled}
          visible={config.enabled}
        />
      </CameraCanvasOverlay>
      {config.enabled && (
        <p className="text-xs text-muted-foreground text-center">
          {t('DetectionConfigPanel.motion.gridHint')}
        </p>
      )}

      {/* Master toggle */}
      <div className="flex items-center justify-between">
        <div className="space-y-0.5">
          <Label className="text-sm font-medium">{t('DetectionConfigPanel.motion.enableLabel')}</Label>
          <p className="text-xs text-muted-foreground">
            {t('DetectionConfigPanel.motion.enableDescription')}
          </p>
        </div>
        <Switch
          checked={config.enabled}
          onCheckedChange={(v) => setConfig({ ...config, enabled: v })}
        />
      </div>

      <Separator />

      {/* Sensitivity */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <Label className="text-sm">{t('DetectionConfigPanel.sensitivity')}</Label>
          <span className="text-xs font-mono tabular-nums text-muted-foreground">
            {config.sensitivity_level}
          </span>
        </div>
        <Slider
          min={1}
          max={100}
          step={1}
          value={[config.sensitivity_level]}
          onValueChange={([v]) => setConfig({ ...config, sensitivity_level: v })}
          disabled={!config.enabled}
          className="w-full"
        />
        <div className="flex justify-between text-[10px] text-muted-foreground">
          <span>{t('DetectionConfigPanel.low')}</span>
          <span>{t('DetectionConfigPanel.high')}</span>
        </div>
      </div>

      <Separator />

      {/* Save */}
      <div className="flex items-center gap-3 justify-end">
        <SaveStatus status={saveStatus} />
        <Button
          size="sm"
          disabled={saveStatus === 'saving'}
          onClick={() => mutation.mutate(config)}
        >
          {saveStatus === 'saving' ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <Save className="h-4 w-4 mr-1" />
          )}
          {t('DetectionConfigPanel.save')}
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-tab: Line Crossing
// ---------------------------------------------------------------------------

function LineCrossingTab({ cameraId }: { cameraId: string }) {
  const { t } = useTranslation('common');
  const qc = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['camera', cameraId, 'line-crossing'],
    queryFn: () => camerasApi.getLineCrossing(cameraId).then((r) => r.data),
  });

  const [config, setConfig] = useState<LineCrossingConfig | null>(null);
  useEffect(() => {
    if (data) setConfig({ ...data, rules: (data.rules ?? []).map((r) => ({ ...r })) });
  }, [data]);

  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'success' | 'error'>('idle');

  const mutation = useMutation({
    mutationFn: (payload: LineCrossingConfig) =>
      camerasApi.setLineCrossing(cameraId, payload),
    onMutate: () => setSaveStatus('saving'),
    onSuccess: () => {
      setSaveStatus('success');
      qc.invalidateQueries({ queryKey: ['camera', cameraId, 'line-crossing'] });
      setTimeout(() => setSaveStatus('idle'), 2000);
    },
    onError: (err) => {
      setSaveStatus('error');
      console.error('[DetectionConfig] Line crossing save failed', err);
      setTimeout(() => setSaveStatus('idle'), 3000);
    },
  });

  const updateRule = (idx: number, patch: Partial<LineCrossingRule>) => {
    if (!config) return;
    const rules = config.rules.map((r, i) => (i === idx ? { ...r, ...patch } : r));
    setConfig({ ...config, rules });
  };

  const [editingIdx, setEditingIdx] = useState<number | null>(null);
  const addRule = () => {
    if (!config) return;
    // These NVRs expose a FIXED set of rule slots, reuse the first disabled
    // (free) slot rather than inventing an id the device doesn't have. Only
    // create a new entry as a fallback for devices that support arbitrary rules.
    const free = config.rules.findIndex((r) => !r.enabled);
    if (free >= 0) {
      updateRule(free, { enabled: true });
      setEditingIdx(free);
      return;
    }
    const nextId = config.rules.reduce((m, r) => Math.max(m, r.id), 0) + 1;
    const rules = [
      ...config.rules,
      { id: nextId, enabled: true, sensitivity: 50, direction: 'both', coordinates: [] },
    ];
    setConfig({ ...config, rules });
    setEditingIdx(rules.length - 1);
  };

  if (isLoading || !config)
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" /> {t('DetectionConfigPanel.loading')}
      </div>
    );

  return (
    <div className="space-y-6">
      {/* Canvas overlay for line crossing rules */}
      {config.rules.length > 0 && (
        <CameraCanvasOverlay cameraId={cameraId} width={560} className="mx-auto">
          <LineOverlay rules={config.rules} />
        </CameraCanvasOverlay>
      )}

      {/* Master toggle */}
      <div className="flex items-center justify-between">
        <div className="space-y-0.5">
          <Label className="text-sm font-medium">{t('DetectionConfigPanel.lineCrossing.enableLabel')}</Label>
          <p className="text-xs text-muted-foreground">
            {t('DetectionConfigPanel.lineCrossing.enableDescription')}
          </p>
        </div>
        <Switch
          checked={config.enabled}
          onCheckedChange={(v) => setConfig({ ...config, enabled: v })}
        />
      </div>

      <Separator />

      {/* Rules */}
      {config.rules.length === 0 && (
        <p className="text-sm text-muted-foreground py-4 text-center">
          {t('DetectionConfigPanel.lineCrossing.noRules')}
        </p>
      )}

      <div className="space-y-4">
        {config.rules.map((rule, idx) => (
          <Card key={rule.id} className="border bg-muted/30">
            <CardContent noOffset className="p-4 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Label className="text-sm font-medium">{t('DetectionConfigPanel.lineCrossing.rule', { id: rule.id })}</Label>
                  <Badge variant="secondary" className="text-[10px] uppercase tracking-wider">
                    {rule.direction || 'both'}
                  </Badge>
                </div>
                <Switch
                  checked={rule.enabled}
                  onCheckedChange={(v) => updateRule(idx, { enabled: v })}
                  disabled={!config.enabled}
                />
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-xs text-muted-foreground">{t('DetectionConfigPanel.sensitivity')}</Label>
                  <span className="text-xs font-mono tabular-nums text-muted-foreground">
                    {rule.sensitivity}
                  </span>
                </div>
                <Slider
                  min={1}
                  max={100}
                  step={1}
                  value={[rule.sensitivity]}
                  onValueChange={([v]) => updateRule(idx, { sensitivity: v })}
                  disabled={!config.enabled || !rule.enabled}
                  className="w-full"
                />
              </div>

              <Button
                type="button"
                size="sm"
                variant="outline"
                className="w-full"
                onClick={() => setEditingIdx(idx)}
              >
                <Pencil className="h-3.5 w-3.5 mr-1" />
                {t('DetectionConfigPanel.editArea', { count: rule.coordinates.length })}
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>

      <Button type="button" variant="outline" size="sm" onClick={addRule}>
        <Plus className="h-4 w-4 mr-1" /> {t('DetectionConfigPanel.lineCrossing.addRule')}
      </Button>

      {editingIdx !== null && config.rules[editingIdx] && (
        <RegionEditDialog
          cameraId={cameraId}
          open={editingIdx !== null}
          onOpenChange={(o) => !o && setEditingIdx(null)}
          title={t('DetectionConfigPanel.lineCrossing.editTitle')}
          mode="line"
          points={config.rules[editingIdx].coordinates}
          onSave={(pts) => updateRule(editingIdx, { coordinates: pts })}
        />
      )}

      <Separator />

      {/* Save */}
      <div className="flex items-center gap-3 justify-end">
        <SaveStatus status={saveStatus} />
        <Button
          size="sm"
          disabled={saveStatus === 'saving'}
          onClick={() => mutation.mutate(config)}
        >
          {saveStatus === 'saving' ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <Save className="h-4 w-4 mr-1" />
          )}
          {t('DetectionConfigPanel.save')}
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-tab: Intrusion Detection
// ---------------------------------------------------------------------------

function IntrusionDetectionTab({ cameraId }: { cameraId: string }) {
  const { t } = useTranslation('common');
  const qc = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['camera', cameraId, 'intrusion-detection'],
    queryFn: () => camerasApi.getIntrusionDetection(cameraId).then((r) => r.data),
  });

  const [config, setConfig] = useState<IntrusionDetectionConfig | null>(null);
  useEffect(() => {
    if (data) setConfig({ ...data, rules: (data.rules ?? []).map((r) => ({ ...r })) });
  }, [data]);

  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'success' | 'error'>('idle');

  const mutation = useMutation({
    mutationFn: (payload: IntrusionDetectionConfig) =>
      camerasApi.setIntrusionDetection(cameraId, payload),
    onMutate: () => setSaveStatus('saving'),
    onSuccess: () => {
      setSaveStatus('success');
      qc.invalidateQueries({ queryKey: ['camera', cameraId, 'intrusion-detection'] });
      setTimeout(() => setSaveStatus('idle'), 2000);
    },
    onError: (err) => {
      setSaveStatus('error');
      console.error('[DetectionConfig] Intrusion detection save failed', err);
      setTimeout(() => setSaveStatus('idle'), 3000);
    },
  });

  const updateRule = (idx: number, patch: Partial<IntrusionDetectionRule>) => {
    if (!config) return;
    const rules = config.rules.map((r, i) => (i === idx ? { ...r, ...patch } : r));
    setConfig({ ...config, rules });
  };

  const [editingIdx, setEditingIdx] = useState<number | null>(null);
  const addRule = () => {
    if (!config) return;
    // Reuse the first disabled (free) fixed slot; only invent a new id as a
    // fallback for devices that support arbitrary rules.
    const free = config.rules.findIndex((r) => !r.enabled);
    if (free >= 0) {
      updateRule(free, { enabled: true });
      setEditingIdx(free);
      return;
    }
    const nextId = config.rules.reduce((m, r) => Math.max(m, r.id), 0) + 1;
    const rules = [
      ...config.rules,
      { id: nextId, enabled: true, sensitivity: 50, time_threshold: 5, coordinates: [] },
    ];
    setConfig({ ...config, rules });
    setEditingIdx(rules.length - 1);
  };

  if (isLoading || !config)
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" /> {t('DetectionConfigPanel.loading')}
      </div>
    );

  return (
    <div className="space-y-6">
      {/* Canvas overlay for intrusion zones */}
      {config.rules.length > 0 && (
        <CameraCanvasOverlay cameraId={cameraId} width={560} className="mx-auto">
          <PolygonOverlay zones={config.rules} />
        </CameraCanvasOverlay>
      )}

      {/* Master toggle */}
      <div className="flex items-center justify-between">
        <div className="space-y-0.5">
          <Label className="text-sm font-medium">{t('DetectionConfigPanel.intrusion.enableLabel')}</Label>
          <p className="text-xs text-muted-foreground">
            {t('DetectionConfigPanel.intrusion.enableDescription')}
          </p>
        </div>
        <Switch
          checked={config.enabled}
          onCheckedChange={(v) => setConfig({ ...config, enabled: v })}
        />
      </div>

      <Separator />

      {config.rules.length === 0 && (
        <p className="text-sm text-muted-foreground py-4 text-center">
          {t('DetectionConfigPanel.intrusion.noZones')}
        </p>
      )}

      <div className="space-y-4">
        {config.rules.map((rule, idx) => (
          <Card key={rule.id} className="border bg-muted/30">
            <CardContent noOffset className="p-4 space-y-4">
              <div className="flex items-center justify-between">
                <Label className="text-sm font-medium">{t('DetectionConfigPanel.intrusion.zone', { id: rule.id })}</Label>
                <Switch
                  checked={rule.enabled}
                  onCheckedChange={(v) => updateRule(idx, { enabled: v })}
                  disabled={!config.enabled}
                />
              </div>

              {/* Sensitivity */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-xs text-muted-foreground">{t('DetectionConfigPanel.sensitivity')}</Label>
                  <span className="text-xs font-mono tabular-nums text-muted-foreground">
                    {rule.sensitivity}
                  </span>
                </div>
                <Slider
                  min={1}
                  max={100}
                  step={1}
                  value={[rule.sensitivity]}
                  onValueChange={([v]) => updateRule(idx, { sensitivity: v })}
                  disabled={!config.enabled || !rule.enabled}
                  className="w-full"
                />
              </div>

              {/* Time threshold */}
              <div className="space-y-1">
                <Label className="text-xs text-muted-foreground">{t('DetectionConfigPanel.intrusion.timeThreshold')}</Label>
                <input
                  type="number"
                  min={0}
                  step={1}
                  value={rule.time_threshold}
                  onChange={(e) =>
                    updateRule(idx, { time_threshold: Math.max(0, Number(e.target.value)) })
                  }
                  disabled={!config.enabled || !rule.enabled}
                  className={cn(
                    'w-24 rounded-md border bg-background px-3 py-1.5 text-sm',
                    'focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring',
                    'disabled:cursor-not-allowed disabled:opacity-50',
                  )}
                />
              </div>

              <Button
                type="button"
                size="sm"
                variant="outline"
                className="w-full"
                onClick={() => setEditingIdx(idx)}
              >
                <Pencil className="h-3.5 w-3.5 mr-1" />
                {t('DetectionConfigPanel.editArea', { count: rule.coordinates.length })}
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>

      <Button type="button" variant="outline" size="sm" onClick={addRule}>
        <Plus className="h-4 w-4 mr-1" /> {t('DetectionConfigPanel.intrusion.addRule')}
      </Button>

      {editingIdx !== null && config.rules[editingIdx] && (
        <RegionEditDialog
          cameraId={cameraId}
          open={editingIdx !== null}
          onOpenChange={(o) => !o && setEditingIdx(null)}
          title={t('DetectionConfigPanel.intrusion.editTitle')}
          mode="polygon"
          points={config.rules[editingIdx].coordinates}
          onSave={(pts) => updateRule(editingIdx, { coordinates: pts })}
        />
      )}

      <Separator />

      {/* Save */}
      <div className="flex items-center gap-3 justify-end">
        <SaveStatus status={saveStatus} />
        <Button
          size="sm"
          disabled={saveStatus === 'saving'}
          onClick={() => mutation.mutate(config)}
        >
          {saveStatus === 'saving' ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <Save className="h-4 w-4 mr-1" />
          )}
          {t('DetectionConfigPanel.save')}
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-tab: Privacy Masks
// ---------------------------------------------------------------------------

function PrivacyMasksTab({ cameraId }: { cameraId: string }) {
  const { t } = useTranslation('common');
  const qc = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['camera', cameraId, 'privacy-masks'],
    queryFn: () => camerasApi.getPrivacyMasks(cameraId).then((r) => r.data),
  });

  const [config, setConfig] = useState<PrivacyMaskConfig | null>(null);
  useEffect(() => {
    if (data) setConfig({ ...data, regions: (data.regions ?? []).map((r) => ({ ...r })) });
  }, [data]);

  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'success' | 'error'>('idle');

  const mutation = useMutation({
    mutationFn: (payload: PrivacyMaskConfig) =>
      camerasApi.setPrivacyMasks(cameraId, payload),
    onMutate: () => setSaveStatus('saving'),
    onSuccess: () => {
      setSaveStatus('success');
      qc.invalidateQueries({ queryKey: ['camera', cameraId, 'privacy-masks'] });
      setTimeout(() => setSaveStatus('idle'), 2000);
    },
    onError: (err) => {
      setSaveStatus('error');
      console.error('[DetectionConfig] Privacy masks save failed', err);
      setTimeout(() => setSaveStatus('idle'), 3000);
    },
  });

  const updateRegion = (idx: number, patch: Partial<PrivacyMaskRegion>) => {
    if (!config) return;
    const regions = config.regions.map((r, i) => (i === idx ? { ...r, ...patch } : r));
    setConfig({ ...config, regions });
  };

  const [editingIdx, setEditingIdx] = useState<number | null>(null);
  const addRegion = () => {
    if (!config) return;
    const free = config.regions.findIndex((r) => !r.enabled);
    if (free >= 0) {
      updateRegion(free, { enabled: true });
      setEditingIdx(free);
      return;
    }
    const nextId = config.regions.reduce((m, r) => Math.max(m, r.id), 0) + 1;
    const regions = [...config.regions, { id: nextId, enabled: true, coordinates: [] }];
    setConfig({ ...config, regions });
    setEditingIdx(regions.length - 1);
  };

  if (isLoading || !config)
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" /> {t('DetectionConfigPanel.loading')}
      </div>
    );

  return (
    <div className="space-y-6">
      {/* Canvas overlay for privacy mask rectangles */}
      {config.regions.length > 0 && (
        <CameraCanvasOverlay cameraId={cameraId} width={560} className="mx-auto">
          <RectangleOverlay regions={config.regions} />
        </CameraCanvasOverlay>
      )}

      {/* Master toggle */}
      <div className="flex items-center justify-between">
        <div className="space-y-0.5">
          <Label className="text-sm font-medium">{t('DetectionConfigPanel.privacy.enableLabel')}</Label>
          <p className="text-xs text-muted-foreground">
            {t('DetectionConfigPanel.privacy.enableDescription')}
          </p>
        </div>
        <Switch
          checked={config.enabled}
          onCheckedChange={(v) => setConfig({ ...config, enabled: v })}
        />
      </div>

      <Separator />

      {config.regions.length === 0 && (
        <p className="text-sm text-muted-foreground py-4 text-center">
          {t('DetectionConfigPanel.privacy.noRegions')}
        </p>
      )}

      <div className="space-y-4">
        {config.regions.map((region, idx) => (
          <Card key={region.id} className="border bg-muted/30">
            <CardContent noOffset className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Label className="text-sm font-medium">{t('DetectionConfigPanel.privacy.region', { id: region.id })}</Label>
                  <Badge variant="secondary" className="text-[10px]">
                    {t('DetectionConfigPanel.privacy.points', { count: region.coordinates.length })}
                  </Badge>
                </div>
                <Switch
                  checked={region.enabled}
                  onCheckedChange={(v) => updateRegion(idx, { enabled: v })}
                  disabled={!config.enabled}
                />
              </div>
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="w-full mt-3"
                onClick={() => setEditingIdx(idx)}
              >
                <Pencil className="h-3.5 w-3.5 mr-1" />
                {t('DetectionConfigPanel.editArea', { count: region.coordinates.length })}
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>

      <Button type="button" variant="outline" size="sm" onClick={addRegion}>
        <Plus className="h-4 w-4 mr-1" /> {t('DetectionConfigPanel.privacy.addRegion')}
      </Button>

      {editingIdx !== null && config.regions[editingIdx] && (
        <RegionEditDialog
          cameraId={cameraId}
          open={editingIdx !== null}
          onOpenChange={(o) => !o && setEditingIdx(null)}
          title={t('DetectionConfigPanel.privacy.editTitle')}
          mode="polygon"
          points={config.regions[editingIdx].coordinates}
          onSave={(pts) => updateRegion(editingIdx, { coordinates: pts })}
        />
      )}

      <Separator />

      {/* Save */}
      <div className="flex items-center gap-3 justify-end">
        <SaveStatus status={saveStatus} />
        <Button
          size="sm"
          disabled={saveStatus === 'saving'}
          onClick={() => mutation.mutate(config)}
        >
          {saveStatus === 'saving' ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <Save className="h-4 w-4 mr-1" />
          )}
          {t('DetectionConfigPanel.save')}
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-tab: Face Detection
// ---------------------------------------------------------------------------

function FaceDetectionTab({ cameraId }: { cameraId: string }) {
  const { t } = useTranslation('common');
  const qc = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['camera', cameraId, 'face-detection'],
    queryFn: () => camerasApi.getFaceDetection(cameraId).then((r) => r.data),
  });

  const [config, setConfig] = useState<FaceDetectionConfig | null>(null);
  useEffect(() => {
    if (data) setConfig({ ...data });
  }, [data]);

  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'success' | 'error'>('idle');

  const mutation = useMutation({
    mutationFn: (payload: Partial<FaceDetectionConfig>) =>
      camerasApi.setFaceDetection(cameraId, payload),
    onMutate: () => setSaveStatus('saving'),
    onSuccess: () => {
      setSaveStatus('success');
      qc.invalidateQueries({ queryKey: ['camera', cameraId, 'face-detection'] });
      setTimeout(() => setSaveStatus('idle'), 2000);
    },
    onError: () => {
      setSaveStatus('error');
      setTimeout(() => setSaveStatus('idle'), 3000);
    },
  });

  if (isLoading || !config)
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" /> {t('DetectionConfigPanel.loading')}
      </div>
    );

  return (
    <div className="space-y-6">
      {/* Master toggle */}
      <div className="flex items-center justify-between">
        <div className="space-y-0.5">
          <Label className="text-sm font-medium">{t('DetectionConfigPanel.face.enableLabel')}</Label>
          <p className="text-xs text-muted-foreground">
            {t('DetectionConfigPanel.face.enableDescription')}
          </p>
        </div>
        <Switch
          checked={config.enabled}
          onCheckedChange={(v) => setConfig({ ...config, enabled: v })}
        />
      </div>

      <Separator />

      {/* Sensitivity */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label className="text-xs text-muted-foreground">{t('DetectionConfigPanel.sensitivity')}</Label>
          <span className="text-xs font-mono tabular-nums text-muted-foreground">
            {config.sensitivity}
          </span>
        </div>
        <Slider
          min={0}
          max={100}
          step={1}
          value={[config.sensitivity]}
          onValueChange={([v]) => setConfig({ ...config, sensitivity: v })}
          disabled={!config.enabled}
          className="w-full"
        />
      </div>

      {/* Snap Interval */}
      <div className="space-y-1">
        <Label className="text-xs text-muted-foreground">{t('DetectionConfigPanel.face.snapInterval')}</Label>
        <input
          type="number"
          min={0}
          step={100}
          value={config.snap_interval}
          onChange={(e) =>
            setConfig({ ...config, snap_interval: Math.max(0, Number(e.target.value)) })
          }
          disabled={!config.enabled}
          className={cn(
            'w-28 rounded-md border bg-background px-3 py-1.5 text-sm',
            'focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring',
            'disabled:cursor-not-allowed disabled:opacity-50',
          )}
        />
      </div>

      {/* Generation Speed */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label className="text-xs text-muted-foreground">{t('DetectionConfigPanel.face.generationSpeed')}</Label>
          <span className="text-xs font-mono tabular-nums text-muted-foreground">
            {config.generation_speed}
          </span>
        </div>
        <Slider
          min={1}
          max={5}
          step={1}
          value={[config.generation_speed]}
          onValueChange={([v]) => setConfig({ ...config, generation_speed: v })}
          disabled={!config.enabled}
          className="w-full"
        />
        <p className="text-[11px] text-muted-foreground">{t('DetectionConfigPanel.face.generationSpeedHint')}</p>
      </div>

      <Separator />

      {/* Save */}
      <div className="flex items-center gap-3 justify-end">
        <SaveStatus status={saveStatus} />
        <Button
          size="sm"
          disabled={saveStatus === 'saving'}
          onClick={() => mutation.mutate(config)}
        >
          {saveStatus === 'saving' ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <Save className="h-4 w-4 mr-1" />
          )}
          {t('DetectionConfigPanel.save')}
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tab descriptor
// ---------------------------------------------------------------------------

interface FeatureTab {
  key: string;
  /** Suffix under DetectionConfigPanel.tabLabels used to translate the tab label. */
  labelKey: string;
  icon: React.ReactNode;
  capKey: keyof SmartCapabilities;
  content: (props: { cameraId: string }) => React.ReactNode;
}

const FEATURE_TABS: FeatureTab[] = [
  {
    key: 'motion',
    labelKey: 'motion',
    icon: <Activity className="h-4 w-4" />,
    capKey: 'motion_detection',
    content: MotionDetectionTab,
  },
  {
    key: 'line-crossing',
    labelKey: 'lineCrossing',
    icon: <ArrowLeftRight className="h-4 w-4" />,
    capKey: 'line_crossing',
    content: LineCrossingTab,
  },
  {
    key: 'intrusion',
    labelKey: 'intrusion',
    icon: <ShieldAlert className="h-4 w-4" />,
    capKey: 'intrusion_detection',
    content: IntrusionDetectionTab,
  },
  {
    key: 'privacy',
    labelKey: 'privacy',
    icon: <EyeOff className="h-4 w-4" />,
    capKey: 'privacy_mask',
    content: PrivacyMasksTab,
  },
  {
    key: 'face',
    labelKey: 'face',
    icon: <ScanFace className="h-4 w-4" />,
    capKey: 'face_detection',
    content: FaceDetectionTab,
  },
];

// ---------------------------------------------------------------------------
// Main panel
// ---------------------------------------------------------------------------

function DetectionConfigPanel({ cameraId, vendor }: DetectionConfigPanelProps) {
  const { t } = useTranslation('common');
  const native = isNativeVendor(vendor);
  const {
    data: capabilities,
    isLoading: capsLoading,
    isError: capsError,
  } = useQuery({
    queryKey: ['camera', cameraId, 'smart-capabilities'],
    queryFn: () => camerasApi.getSmartCapabilities(cameraId).then((r) => r.data),
    // Non-native (generic ONVIF) cameras don't expose smart-config, skip the call.
    enabled: native,
  });

  // Determine first supported tab for default selection
  const firstSupported = capabilities
    ? FEATURE_TABS.find((t) => capabilities[t.capKey])?.key ?? FEATURE_TABS[0].key
    : FEATURE_TABS[0].key;

  const [activeTab, setActiveTab] = useState<string>(firstSupported);
  const hasSetDefault = useRef(false);

  // Sync default when capabilities arrive · only once
  useEffect(() => {
    if (capabilities && !hasSetDefault.current) {
      const first = FEATURE_TABS.find((t) => capabilities[t.capKey])?.key;
      if (first) {
        setActiveTab(first);
        hasSetDefault.current = true;
      }
    }
  }, [capabilities]);

  // Non-native vendor: zones & masks aren't available via generic ONVIF, show
  // the honest note instead of a (failing) capabilities probe.
  if (!native)
    return (
      <Card>
        <CardContent noOffset className="p-4">
          <VendorCapabilityNote vendor={vendor} feature="zones" />
        </CardContent>
      </Card>
    );

  if (capsLoading)
    return (
      <Card>
        <CardContent noOffset className="flex items-center justify-center py-16 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin mr-2" /> {t('DetectionConfigPanel.loadingCapabilities')}
        </CardContent>
      </Card>
    );

  if (capsError || !capabilities)
    return (
      <Card>
        <EmptyState
          icon={XCircle}
          title={t('DetectionConfigPanel.capabilitiesError.title')}
          description={t('DetectionConfigPanel.capabilitiesError.description')}
        />
      </Card>
    );

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">{t('DetectionConfigPanel.title')}</CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="justify-start mb-4">
            {FEATURE_TABS.map((tab) => {
              const supported = capabilities[tab.capKey];
              return (
                <TabsTrigger
                  key={tab.key}
                  value={tab.key}
                  disabled={!supported}
                  className="gap-1.5 text-xs data-[state=active]:shadow-sm"
                >
                  {tab.icon}
                  {t(`DetectionConfigPanel.tabLabels.${tab.labelKey}`)}
                  {!supported && (
                    <Badge
                      variant="outline"
                      className="ml-1 text-[9px] px-1 py-0 leading-tight text-muted-foreground"
                    >
                      {t('DetectionConfigPanel.notAvailableShort')}
                    </Badge>
                  )}
                </TabsTrigger>
              );
            })}
          </TabsList>

          {FEATURE_TABS.map((tab) => {
            const supported = capabilities[tab.capKey];
            const Content = tab.content;
            return (
              <TabsContent key={tab.key} value={tab.key} className="mt-0">
                {supported ? (
                  <Content cameraId={cameraId} />
                ) : (
                  <div className="flex flex-col items-center justify-center py-12 gap-2 text-muted-foreground">
                    <NotSupportedBadge />
                    <p className="text-sm mt-1">
                      {t('DetectionConfigPanel.unsupportedFeature', {
                        feature: t(`DetectionConfigPanel.tabLabels.${tab.labelKey}`).toLowerCase(),
                      })}
                    </p>
                  </div>
                )}
              </TabsContent>
            );
          })}
        </Tabs>
      </CardContent>
    </Card>
  );
}

export default DetectionConfigPanel;
