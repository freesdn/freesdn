// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * ScanWizard - Multi-step scan configuration wizard.
 * 
 * Steps: Scan Type → Target → Options → Review & Start
 */

import { useState, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Network,
  Server,
  ChevronRight,
  ChevronLeft,
  Play,
  Settings2,
  Building2,
  Loader2,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { cn } from '@/lib/utils';
import type { ScanRequest } from '@/lib/api';

interface SiteItem {
  id: string;
  name: string;
  subnets?: Array<{ cidr: string; name?: string }>;
}

interface ControllerItem {
  id: string;
  name: string;
  type: string;
  host: string;
  site_id: string;
}

interface ScanWizardProps {
  sites: SiteItem[];
  controllers: ControllerItem[];
  onStartScan: (request: ScanRequest) => void;
  // Controller-type scans don't go through /discovery/scan (which requires
  // IP-range targets). They trigger adapter-based discovery on an already
  // registered Controller, keyed by its UUID, a separate endpoint.
  onStartControllerScan: (controllerId: string) => void;
  onCancel: () => void;
  isLoading?: boolean;
}

type ScanType = 'subnet' | 'controller';

type TFunc = (key: string, options?: Record<string, unknown>) => string;

const buildSteps = (t: TFunc) => [
  { title: t('ScanWizard.steps.scanType.title'), description: t('ScanWizard.steps.scanType.description') },
  { title: t('ScanWizard.steps.target.title'), description: t('ScanWizard.steps.target.description') },
  { title: t('ScanWizard.steps.options.title'), description: t('ScanWizard.steps.options.description') },
  { title: t('ScanWizard.steps.review.title'), description: t('ScanWizard.steps.review.description') },
];

export default function ScanWizard({ sites, controllers, onStartScan, onStartControllerScan, onCancel, isLoading }: ScanWizardProps) {
  const { t } = useTranslation('common');
  const STEPS = buildSteps(t);
  const [currentStep, setCurrentStep] = useState(0);
  const [scanType, setScanType] = useState<ScanType>('subnet');
  const [selectedSite, setSelectedSite] = useState('');
  const [subnet, setSubnet] = useState('');
  const [selectedController, setSelectedController] = useState('');
  const [fingerprintDevices, setFingerprintDevices] = useState(true);
  const [autoAdopt, setAutoAdopt] = useState(false);
  const [portScan, setPortScan] = useState(true);
  const [timeout, setTimeout_] = useState(5);
  const [threads, setThreads] = useState(10);

  // Controllers belonging to the chosen site, the controller-discovery
  // endpoint operates on an already-registered Controller, so the wizard
  // picks one rather than asking for a free-text URL it can't dispatch.
  const siteControllers = controllers.filter((c) => c.site_id === selectedSite);

  const canProceed = useCallback(() => {
    switch (currentStep) {
      case 0:
        return true;
      case 1:
        if (scanType === 'subnet') return selectedSite && subnet.trim();
        return selectedSite && selectedController;
      case 2:
        return true;
      case 3:
        return true;
      default:
        return false;
    }
  }, [currentStep, scanType, selectedSite, subnet, selectedController]);

  const handleStartScan = useCallback(() => {
    // Controller scans use the adapter-discovery endpoint (keyed by the
    // registered controller's UUID), NOT the IP-range /discovery/scan path.
    if (scanType === 'controller') {
      if (selectedController) onStartControllerScan(selectedController);
      return;
    }
    const targets = subnet.split(/[,\n]+/).map(t => t.trim()).filter(Boolean);
    const request: ScanRequest = {
      site_id: selectedSite,
      scan_type: scanType,
      targets,
      subnets: targets,
      // Map wizard toggles to the backend ScanOptionsSchema field names.
      // (port_scan / auto_adopt have no server-side equivalent and were being
      // silently dropped, they stay UI-only.)
      options: {
        probe_services: fingerprintDevices,
        resolve_hostnames: true,
        tcp_timeout: timeout,
        max_concurrent_hosts: threads,
      },
    };
    onStartScan(request);
  }, [scanType, selectedSite, subnet, selectedController, fingerprintDevices, timeout, threads, onStartScan, onStartControllerScan]);

  // Auto-fill subnet from site; reset the controller pick (it's site-scoped)
  const handleSiteChange = (siteId: string) => {
    setSelectedSite(siteId);
    setSelectedController('');
    const site = sites.find(s => s.id === siteId);
    if (site?.subnets?.length) {
      setSubnet(site.subnets.map(s => s.cidr).join('\n'));
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Settings2 className="h-5 w-5 text-primary" />
          {t('ScanWizard.title')}
        </CardTitle>
        {/* Step indicator */}
        <div className="flex items-center gap-2 mt-3">
          {STEPS.map((_step, i) => (
            <div key={i} className="flex items-center gap-2">
              <div
                className={cn(
                  'w-7 h-7 rounded-full flex items-center justify-center text-xs font-medium border transition-colors',
                  i < currentStep
                    ? 'bg-primary text-primary-foreground border-primary'
                    : i === currentStep
                    ? 'bg-primary/10 text-primary border-primary'
                    : 'bg-muted text-muted-foreground border-border',
                )}
              >
                {i + 1}
              </div>
              {i < STEPS.length - 1 && (
                <div
                  className={cn(
                    'w-8 h-0.5 rounded',
                    i < currentStep ? 'bg-primary' : 'bg-border',
                  )}
                />
              )}
            </div>
          ))}
          <span className="ml-3 text-sm font-medium">{STEPS[currentStep].title}</span>
          <span className="text-xs text-muted-foreground">- {STEPS[currentStep].description}</span>
        </div>
      </CardHeader>

      <CardContent className="space-y-6">
        {/* STEP 0: Scan Type */}
        {currentStep === 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div
              onClick={() => setScanType('subnet')}
              className={cn(
                'p-6 rounded-lg border-2 cursor-pointer transition-all',
                scanType === 'subnet'
                  ? 'border-primary bg-primary/5'
                  : 'border-border hover:border-primary/30',
              )}
            >
              <Network className="h-8 w-8 text-primary mb-3" />
              <h3 className="font-semibold mb-1">{t('ScanWizard.scanTypes.subnet.title')}</h3>
              <p className="text-sm text-muted-foreground mb-3">
                {t('ScanWizard.scanTypes.subnet.description')}
              </p>
              <div className="flex flex-wrap gap-1">
                <Badge variant="secondary" className="text-[10px]">ICMP</Badge>
                <Badge variant="secondary" className="text-[10px]">{t('ScanWizard.scanTypes.subnet.badges.portScan')}</Badge>
                <Badge variant="secondary" className="text-[10px]">{t('ScanWizard.scanTypes.subnet.badges.fingerprint')}</Badge>
                <Badge variant="secondary" className="text-[10px]">mDNS/SSDP</Badge>
              </div>
            </div>
            <div
              onClick={() => setScanType('controller')}
              className={cn(
                'p-6 rounded-lg border-2 cursor-pointer transition-all',
                scanType === 'controller'
                  ? 'border-primary bg-primary/5'
                  : 'border-border hover:border-primary/30',
              )}
            >
              <Server className="h-8 w-8 text-primary mb-3" />
              <h3 className="font-semibold mb-1">{t('ScanWizard.scanTypes.controller.title')}</h3>
              <p className="text-sm text-muted-foreground mb-3">
                {t('ScanWizard.scanTypes.controller.description')}
              </p>
              <div className="flex flex-wrap gap-1">
                <Badge variant="secondary" className="text-[10px]">Omada</Badge>
                <Badge variant="secondary" className="text-[10px]">Hikvision</Badge>
                <Badge variant="secondary" className="text-[10px]">{t('ScanWizard.scanTypes.controller.badges.autoSync')}</Badge>
              </div>
            </div>
          </div>
        )}

        {/* STEP 1: Target */}
        {currentStep === 1 && (
          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">{t('ScanWizard.fields.site')}</label>
              <Select value={selectedSite} onValueChange={handleSiteChange}>
                <SelectTrigger>
                  <SelectValue placeholder={t('ScanWizard.fields.sitePlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  {sites.map(site => (
                    <SelectItem key={site.id} value={site.id}>
                      <div className="flex items-center gap-2">
                        <Building2 className="h-4 w-4" />
                        {site.name}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {scanType === 'subnet' ? (
              <div className="space-y-2">
                <label className="text-sm font-medium">{t('ScanWizard.fields.subnet')}</label>
                <textarea
                  className="w-full min-h-[100px] p-3 rounded-md border bg-background text-sm font-mono resize-y"
                  placeholder={'192.168.1.0/24\n10.0.0.1-50\n172.16.0.100'}
                  value={subnet}
                  onChange={(e) => setSubnet(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  {t('ScanWizard.fields.subnetHelper')}
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                <label className="text-sm font-medium">{t('ScanWizard.fields.controller')}</label>
                {!selectedSite ? (
                  <p className="text-sm text-muted-foreground">
                    {t('ScanWizard.fields.controllerSelectSiteFirst')}
                  </p>
                ) : siteControllers.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    {t('ScanWizard.fields.controllerNone')}
                  </p>
                ) : (
                  <Select value={selectedController} onValueChange={setSelectedController}>
                    <SelectTrigger>
                      <SelectValue placeholder={t('ScanWizard.fields.controllerPlaceholder')} />
                    </SelectTrigger>
                    <SelectContent>
                      {siteControllers.map((c) => (
                        <SelectItem key={c.id} value={c.id}>
                          <div className="flex items-center gap-2">
                            <Server className="h-4 w-4" />
                            {c.name}
                            <span className="text-xs text-muted-foreground">· {c.type}</span>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              </div>
            )}
          </div>
        )}

        {/* STEP 2: Options */}
        {currentStep === 2 && (
          <div className="space-y-4">
            <div className="space-y-3">
              <label className="flex items-center gap-3 cursor-pointer p-3 rounded-lg border hover:bg-muted/30">
                <Checkbox checked={fingerprintDevices} onCheckedChange={(v) => setFingerprintDevices(!!v)} />
                <div>
                  <p className="text-sm font-medium">{t('ScanWizard.options.fingerprint.title')}</p>
                  <p className="text-xs text-muted-foreground">{t('ScanWizard.options.fingerprint.description')}</p>
                </div>
              </label>
              <label className="flex items-center gap-3 cursor-pointer p-3 rounded-lg border hover:bg-muted/30">
                <Checkbox checked={portScan} onCheckedChange={(v) => setPortScan(!!v)} />
                <div>
                  <p className="text-sm font-medium">{t('ScanWizard.options.portScan.title')}</p>
                  <p className="text-xs text-muted-foreground">{t('ScanWizard.options.portScan.description')}</p>
                </div>
              </label>
              <label className="flex items-center gap-3 cursor-pointer p-3 rounded-lg border hover:bg-muted/30">
                <Checkbox checked={autoAdopt} onCheckedChange={(v) => setAutoAdopt(!!v)} />
                <div>
                  <p className="text-sm font-medium">{t('ScanWizard.options.autoAdopt.title')}</p>
                  <p className="text-xs text-muted-foreground">{t('ScanWizard.options.autoAdopt.description')}</p>
                </div>
              </label>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">{t('ScanWizard.options.timeout')}</label>
                <Input
                  type="number"
                  min={1}
                  max={30}
                  value={timeout}
                  onChange={(e) => setTimeout_(parseInt(e.target.value) || 5)}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">{t('ScanWizard.options.threads')}</label>
                <Input
                  type="number"
                  min={1}
                  max={50}
                  value={threads}
                  onChange={(e) => setThreads(parseInt(e.target.value) || 10)}
                />
              </div>
            </div>
          </div>
        )}

        {/* STEP 3: Review */}
        {currentStep === 3 && (
          <div className="space-y-4">
            <div className="p-4 rounded-lg bg-muted/50 space-y-3">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">{t('ScanWizard.review.scanType')}</span>
                <Badge variant="outline">{scanType === 'subnet' ? t('ScanWizard.scanTypes.subnet.title') : t('ScanWizard.scanTypes.controller.title')}</Badge>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">{t('ScanWizard.review.site')}</span>
                <span className="font-medium">{sites.find(s => s.id === selectedSite)?.name || '-'}</span>
              </div>
              {scanType === 'subnet' ? (
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">{t('ScanWizard.review.targets')}</span>
                  <span className="font-mono text-xs">{t('ScanWizard.review.targetCount', { count: subnet.split(/[,\n]+/).filter(Boolean).length })}</span>
                </div>
              ) : (
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">{t('ScanWizard.review.controller')}</span>
                  <span className="font-mono text-xs">
                    {siteControllers.find((c) => c.id === selectedController)?.name || '-'}
                  </span>
                </div>
              )}
              <div className="flex flex-wrap gap-2 mt-2">
                {fingerprintDevices && <Badge variant="secondary">{t('ScanWizard.options.fingerprint.title')}</Badge>}
                {portScan && <Badge variant="secondary">{t('ScanWizard.options.portScan.title')}</Badge>}
                {autoAdopt && <Badge variant="secondary">{t('ScanWizard.options.autoAdopt.title')}</Badge>}
                <Badge variant="outline">{t('ScanWizard.review.timeoutBadge', { seconds: timeout })}</Badge>
                <Badge variant="outline">{t('ScanWizard.review.threadsBadge', { count: threads })}</Badge>
              </div>
            </div>
            <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/20 text-sm text-blue-700 dark:text-blue-300">
              {t('ScanWizard.review.info')}
            </div>
          </div>
        )}

        {/* Navigation */}
        <div className="flex items-center justify-between pt-4 border-t">
          <div>
            {currentStep > 0 && (
              <Button variant="ghost" onClick={() => setCurrentStep(s => s - 1)} className="gap-2">
                <ChevronLeft className="h-4 w-4" />
                {t('ScanWizard.actions.back')}
              </Button>
            )}
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={onCancel}>{t('ScanWizard.actions.cancel')}</Button>
            {currentStep < STEPS.length - 1 ? (
              <Button onClick={() => setCurrentStep(s => s + 1)} disabled={!canProceed()} className="gap-2">
                {t('ScanWizard.actions.next')}
                <ChevronRight className="h-4 w-4" />
              </Button>
            ) : (
              <Button onClick={handleStartScan} disabled={isLoading} className="gap-2">
                {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                {t('ScanWizard.actions.startScan')}
              </Button>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
