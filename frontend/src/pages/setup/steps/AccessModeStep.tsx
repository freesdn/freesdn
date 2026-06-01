// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Setup Wizard: Access Mode Step
 *
 * Lets a new install opt into read-only ("Monitor only") up front,
 * before any controllers are added. The choice is purely client-state
 * here, the Complete step flips adapter read-only on via the system
 * API when "monitor" is selected.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useSetupStore, type AccessMode } from '@/stores/setupStore';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import {
  Pencil,
  Eye,
  CheckCircle2,
  ChevronRight,
  ChevronLeft,
} from 'lucide-react';

interface AccessModeStepProps {
  onNext: () => void;
  onPrevious: () => void;
}

const MODE_ICONS: Record<AccessMode, React.ElementType> = {
  manage: Pencil,
  monitor: Eye,
};

export function AccessModeStep({ onNext, onPrevious }: AccessModeStepProps) {
  const { t } = useTranslation('setup');
  const { accessMode, setAccessMode } = useSetupStore();
  // Restore from store (e.g. after refresh); default is "manage".
  const [selected, setSelected] = useState<AccessMode>(accessMode || 'manage');

  const handleSubmit = () => {
    setAccessMode(selected);
    onNext();
  };

  const modes: AccessMode[] = ['manage', 'monitor'];

  return (
    <div className="flex flex-col min-h-full">
      <div className="flex-1 space-y-6">
        <div>
          <h1 className="text-2xl font-bold">{t('AccessModeStep.title')}</h1>
          <p className="text-muted-foreground mt-1">
            {t('AccessModeStep.subtitle')}
          </p>
        </div>

        <div role="radiogroup" aria-label={t('AccessModeStep.title')} className="space-y-4">
          {modes.map((mode) => {
            const Icon = MODE_ICONS[mode];
            const isSelected = selected === mode;
            return (
              <Card
                key={mode}
                role="radio"
                aria-checked={isSelected}
                tabIndex={0}
                onClick={() => setSelected(mode)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    setSelected(mode);
                  }
                }}
                className={cn(
                  'cursor-pointer transition-colors',
                  isSelected
                    ? 'border-primary ring-1 ring-primary bg-primary/5'
                    : 'border-border hover:border-accent',
                )}
              >
                <CardContent noOffset className="flex items-start gap-4 p-4">
                  <div
                    className={cn(
                      'flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg',
                      isSelected ? 'bg-primary/10 text-primary' : 'bg-accent text-muted-foreground',
                    )}
                  >
                    <Icon className="h-5 w-5" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="font-medium">{t(`AccessModeStep.modes.${mode}.title`)}</p>
                      {mode === 'manage' && (
                        <span className="text-xs text-muted-foreground">
                          {t('AccessModeStep.defaultBadge')}
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">
                      {t(`AccessModeStep.modes.${mode}.description`)}
                    </p>
                  </div>
                  {isSelected && (
                    <CheckCircle2 className="h-5 w-5 flex-shrink-0 text-primary" />
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>

        <div className="p-4 bg-accent/50 rounded-lg">
          <p className="text-xs text-muted-foreground">
            {t('AccessModeStep.hint')}
          </p>
        </div>
      </div>

      <div className="sticky bottom-0 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80 border-t border-border/50 pt-4 pb-4 -mx-1 px-1 mt-6">
        <div className="flex justify-between">
          <Button variant="outline" onClick={onPrevious}>
            <ChevronLeft className="mr-2 h-4 w-4" />
            {t('AccessModeStep.actions.previous')}
          </Button>
          <Button onClick={handleSubmit}>
            {t('AccessModeStep.actions.continue')}
            <ChevronRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}
