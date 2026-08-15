// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Setup Wizard: Modules Step
 */
import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { setupApi, type ModuleOption } from '@/lib/setup-api';
import { getApiErrorMessage } from '@/lib/api';
import { useSetupStore } from '@/stores/setupStore';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Badge } from '@/components/ui/badge';
import {
  Loader2,
  Puzzle,
  ChevronRight,
  ChevronLeft,
  Network,
  Camera,
  Phone,
  Lock,
  Shield,
  HardDrive,
  Sparkles,
  Radio,
  Server,
} from 'lucide-react';

interface ModulesStepProps {
  onNext: () => void;
  onPrevious: () => void;
}

const MODULE_ICONS: Record<string, React.ElementType> = {
  network: Network,
  cameras: Camera,
  voip: Phone,
  access_control: Lock,
  firewall: Shield,
  backup: HardDrive,
  ai: Sparkles,
  collector: Radio,
  hypervisor: Server,
};

export function ModulesStep({ onNext, onPrevious }: ModulesStepProps) {
  const { t } = useTranslation('setup');
  const { organizationId, enabledModules, setEnabledModules, setAvailableModules, availableModules } = useSetupStore();
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [modules, setModules] = useState<ModuleOption[]>([]);
  // Restore from store if user already selected modules (e.g. after refresh)
  const [selected, setSelected] = useState<Set<string>>(
    () => enabledModules.length > 0 ? new Set(enabledModules) : new Set(['network', 'backup', 'ai'])
  );
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadModules = async () => {
      try {
        const data = await setupApi.getModules();
        setModules(data);
        setAvailableModules(data);

        // Pre-select recommended modules only if user hasn't already chosen
        if (enabledModules.length === 0) {
          const recommended = data.filter(m => m.recommended).map(m => m.id);
          setSelected(new Set(recommended));
        }
      } catch (_err) {
        setError(t('ModulesStep.errors.loadFailed'));
      } finally {
        setLoading(false);
      }
    };

    if (availableModules.length > 0) {
      setModules(availableModules);
      setLoading(false);
    } else {
      loadModules();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps -- only run on mount/store restore
  }, [availableModules, setAvailableModules]);

  const handleToggle = (moduleId: string) => {
    const newSelected = new Set(selected);
    
    if (newSelected.has(moduleId)) {
      // Check if any module depends on this one
      const dependents = modules.filter(m => m.requires?.includes(moduleId) && newSelected.has(m.id));
      if (dependents.length > 0) {
        setError(t('ModulesStep.errors.cannotDisable', { dependents: dependents.map(d => d.name).join(', ') }));
        return;
      }
      newSelected.delete(moduleId);
    } else {
      // Auto-select dependencies
      const module = modules.find(m => m.id === moduleId);
      if (module?.requires) {
        module.requires.forEach(dep => newSelected.add(dep));
      }
      newSelected.add(moduleId);
    }
    
    setSelected(newSelected);
    setError(null);
  };

  const handleSubmit = async () => {
    setSubmitting(true);
    setError(null);
    
    try {
      const response = await setupApi.enableModules({
        enabled_modules: Array.from(selected),
        organization_id: organizationId,
      });
      
      if (response.success) {
        setEnabledModules(Array.from(selected));
        onNext();
      } else {
        setError(response.error || t('ModulesStep.errors.enableFailed'));
      }
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, t('ModulesStep.errors.enableFailed')));
    } finally {
      setSubmitting(false);
    }
  };

  // Group modules by category
  const groupedModules = (modules ?? []).reduce((acc, module) => {
    if (!acc[module.category]) {
      acc[module.category] = [];
    }
    acc[module.category].push(module);
    return acc;
  }, {} as Record<string, ModuleOption[]>);

  if (loading) {
    return (
      <Card>
        <CardContent noOffset className="py-12 flex items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="flex flex-col min-h-full">
      <div className="flex-1 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">{t('ModulesStep.title')}</h1>
        <p className="text-muted-foreground mt-1">
          {t('ModulesStep.subtitle')}
        </p>
      </div>

      {Object.entries(groupedModules).map(([category, categoryModules]) => (
        <Card key={category}>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-lg">
              <Puzzle className="h-5 w-5" />
              {category}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {categoryModules.map((module) => {
                const Icon = MODULE_ICONS[module.id] || Puzzle;
                const isSelected = selected.has(module.id);
                const isDependency = Array.from(selected).some(
                  id => modules.find(m => m.id === id)?.requires?.includes(module.id)
                );

                return (
                  <div
                    key={module.id}
                    className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                      isSelected 
                        ? 'bg-primary/5 border-primary/30' 
                        : 'bg-accent/30 border-transparent hover:border-accent'
                    }`}
                    onClick={() => handleToggle(module.id)}
                  >
                    <Checkbox
                      checked={isSelected}
                      disabled={isDependency}
                      className="mt-1"
                    />
                    <Icon className="h-5 w-5 mt-0.5 flex-shrink-0 text-muted-foreground" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="font-medium">{module.name}</p>
                        {module.recommended && (
                          <Badge variant="secondary" className="text-xs">
                            {t('ModulesStep.badges.recommended')}
                          </Badge>
                        )}
                        {isDependency && (
                          <Badge variant="outline" className="text-xs">
                            {t('ModulesStep.badges.required')}
                          </Badge>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">
                        {module.description}
                      </p>
                      {module.requires && module.requires.length > 0 && (
                        <p className="text-xs text-muted-foreground mt-1">
                          {t('ModulesStep.requires', { modules: module.requires.join(', ') })}
                        </p>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      ))}

      {error && (
        <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      <div className="p-4 bg-accent/50 rounded-lg">
        <p className="text-sm text-muted-foreground">
          <strong>{t('ModulesStep.selected.label')}</strong> {t('ModulesStep.selected.count', { count: selected.size })}
        </p>
        <p className="text-xs text-muted-foreground mt-1">
          {t('ModulesStep.selected.hint')}
        </p>
      </div>

      </div>

      <div className="sticky bottom-0 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80 border-t border-border/50 pt-4 pb-4 -mx-1 px-1 mt-6">
        <div className="flex justify-between">
          <Button variant="outline" onClick={onPrevious}>
            <ChevronLeft className="mr-2 h-4 w-4" />
            {t('ModulesStep.actions.previous')}
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={submitting || selected.size === 0}
          >
            {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {t('ModulesStep.actions.continue')}
            <ChevronRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}
