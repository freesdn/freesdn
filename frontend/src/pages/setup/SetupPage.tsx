// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Setup Wizard Page
 *
 * Responsive layout: full sidebar on md+, compact header on mobile.
 */
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/utils';
import { setupApi } from '@/lib/setup-api';
import { useSetupStore } from '@/stores/setupStore';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  CheckCircle,
  Circle,
  Loader2,
  ServerCog,
  Shield,
  Building2,
  Puzzle,
  Network,
  PartyPopper,
  KeyRound,
  Menu,
  X,
} from 'lucide-react';
import { ThemeToggle } from '@/components/ui/theme-toggle';

// Step Components
import { WelcomeStep } from './steps/WelcomeStep';
import { DatabaseStep } from './steps/DatabaseStep';
import { AdminStep } from './steps/AdminStep';
import { OrganizationStep } from './steps/OrganizationStep';
import { ModulesStep } from './steps/ModulesStep';
import { AccessModeStep } from './steps/AccessModeStep';
import { ControllersStep } from './steps/ControllersStep';
import { CompleteStep } from './steps/CompleteStep';

// IMPORTANT ordering note (v2.6+): Organization comes BEFORE Admin.
// The backend uses super_admin existence as the
// ``require_setup_incomplete`` gate, the moment the Admin step
// succeeds, the gate closes and every subsequent ``/setup/*`` call
// returns 403. Previously the wizard ran Admin → Organization, which
// meant the Organization step always failed silently and the new
// super_admin was left with ``organization_id=NULL``. The reordered
// flow collects org details first (purely client-state) so the
// Admin step can submit user + org together to the new atomic
// ``/setup/admin`` endpoint that creates both in one transaction.
const STEPS = [
  { id: 0, nameKey: 'welcome', icon: ServerCog, descKey: 'welcome' },
  { id: 1, nameKey: 'database', icon: ServerCog, descKey: 'database' },
  { id: 2, nameKey: 'organization', icon: Building2, descKey: 'organization' },
  { id: 3, nameKey: 'admin', icon: Shield, descKey: 'admin' },
  { id: 4, nameKey: 'modules', icon: Puzzle, descKey: 'modules' },
  // Access mode (Manage vs Monitor-only) is chosen BEFORE controllers
  // so the user opts into read-only up front, before any device is added.
  { id: 5, nameKey: 'accessMode', icon: KeyRound, descKey: 'accessMode' },
  { id: 6, nameKey: 'controllers', icon: Network, descKey: 'controllers' },
  { id: 7, nameKey: 'complete', icon: PartyPopper, descKey: 'complete' },
];

export default function SetupPage() {
  const navigate = useNavigate();
  const { t } = useTranslation('setup');
  const { currentStep, setCurrentStep, stepsCompleted, markStepCompleted, environment } = useSetupStore();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Check setup status on mount
  useEffect(() => {
    const checkStatus = async () => {
      try {
        const status = await setupApi.getStatus();
        if (status.is_complete) {
          navigate('/login');
          return;
        }
        setLoading(false);
      } catch (_err) {
        setError(t('SetupPage.errors.checkStatus'));
        setLoading(false);
      }
    };
    checkStatus();
  }, [navigate, t]);

  const handleNext = () => {
    markStepCompleted(currentStep);
    if (currentStep < STEPS.length - 1) {
      setCurrentStep(currentStep + 1);
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleStepClick = (stepId: number) => {
    if (stepsCompleted.includes(stepId) || stepId === currentStep || stepId === currentStep + 1) {
      setCurrentStep(stepId);
      setMobileMenuOpen(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <Card className="max-w-md w-full">
          <CardHeader>
            <CardTitle className="text-destructive">{t('SetupPage.errors.title')}</CardTitle>
          </CardHeader>
          <CardContent>
            <p>{error}</p>
            <Button className="mt-4" onClick={() => window.location.reload()}>
              {t('SetupPage.actions.retry')}
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const progressPercent = ((currentStep + 1) / STEPS.length) * 100;
  const currentStepMeta = STEPS[currentStep] ?? STEPS[0];

  /* -- Sidebar content (shared between desktop & mobile overlay) -- */
  const sidebarNav = (
    <nav className="flex-1 space-y-1">
      {STEPS.map((step) => {
        const isCompleted = stepsCompleted.includes(step.id);
        const isCurrent = currentStep === step.id;
        const isClickable = isCompleted || isCurrent || step.id === currentStep + 1;
        const Icon = step.icon;

        return (
          <button
            key={step.id}
            onClick={() => handleStepClick(step.id)}
            disabled={!isClickable}
            className={cn(
              'w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition-colors',
              isCurrent && 'bg-primary/10 text-primary',
              isCompleted && !isCurrent && 'text-primary',
              !isCompleted && !isCurrent && 'text-muted-foreground',
              isClickable && 'hover:bg-accent cursor-pointer',
              !isClickable && 'cursor-not-allowed opacity-50'
            )}
          >
            {isCompleted ? (
              <CheckCircle className="h-5 w-5 text-primary flex-shrink-0" />
            ) : isCurrent ? (
              <Icon className="h-5 w-5 flex-shrink-0" />
            ) : (
              <Circle className="h-5 w-5 flex-shrink-0" />
            )}
            <div>
              <p className="font-medium text-sm">{t(`SetupPage.steps.${step.nameKey}.name`)}</p>
              <p className="text-xs text-muted-foreground">{t(`SetupPage.steps.${step.descKey}.description`)}</p>
            </div>
          </button>
        );
      })}
    </nav>
  );

  return (
    <div className="h-screen bg-background flex flex-col md:flex-row overflow-hidden">
      {/* ===== Mobile header ===== */}
      <header className="md:hidden bg-card border-b border-border px-4 py-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-primary to-primary/80 flex items-center justify-center shadow-sm">
              <Network className="h-4 w-4 text-primary-foreground" />
            </div>
            <div>
              <p className="text-sm font-semibold">{t('SetupPage.header.mobileTitle')}</p>
              <p className="text-xs text-muted-foreground">
                {t('SetupPage.header.mobileStep', {
                  current: currentStep + 1,
                  total: STEPS.length,
                  step: t(`SetupPage.steps.${currentStepMeta.nameKey}.name`),
                })}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-1">
            <ThemeToggle variant="icon" />
            <button
              onClick={() => setMobileMenuOpen(v => !v)}
              className="p-2 rounded-md hover:bg-accent text-muted-foreground"
            >
              {mobileMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>
          </div>
        </div>
        {/* Progress bar */}
        <div className="mt-2 h-1 bg-secondary rounded-full overflow-hidden">
          <div
            className="h-full bg-primary transition-all duration-300 rounded-full"
            style={{ width: `${progressPercent}%` }}
          />
        </div>
      </header>

      {/* ===== Mobile step overlay ===== */}
      {mobileMenuOpen && (
        <div className="md:hidden fixed inset-0 z-50 bg-background/80 backdrop-blur-sm" onClick={() => setMobileMenuOpen(false)}>
          <div
            className="absolute top-0 left-0 w-72 max-w-[90vw] h-full bg-card border-r border-border p-6 shadow-lg overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-6">
              <div className="flex items-center gap-3">
                <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-primary to-primary/80 flex items-center justify-center shadow-lg shadow-primary/20">
                  <Network className="h-5 w-5 text-primary-foreground" />
                </div>
                <h1 className="text-xl font-bold text-primary">FreeSDN</h1>
              </div>
              <p className="text-sm text-muted-foreground mt-1">{t('SetupPage.header.wizard')}</p>
            </div>
            {sidebarNav}
          </div>
        </div>
      )}

      {/* ===== Desktop sidebar ===== */}
      <aside className="hidden md:flex w-72 bg-card border-r border-border p-6 flex-col flex-shrink-0">
        <div className="mb-8">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-primary to-primary/80 flex items-center justify-center shadow-lg shadow-primary/20">
              <Network className="h-5 w-5 text-primary-foreground" />
            </div>
            <h1 className="text-2xl font-bold text-primary">FreeSDN</h1>
          </div>
          <p className="text-sm text-muted-foreground mt-1">{t('SetupPage.header.wizard')}</p>
          {environment && (
            <Badge
              variant={environment === 'production' ? 'default' : 'secondary'}
              className="mt-2"
            >
              {environment === 'production' ? t('SetupPage.environment.production') : t('SetupPage.environment.development')}
            </Badge>
          )}
        </div>

        {sidebarNav}

        <div className="mt-auto pt-6 border-t border-border">
          <div className="flex items-center justify-between mb-2">
            <p className="text-xs text-muted-foreground">
              {t('SetupPage.header.stepOf', { current: currentStep + 1, total: STEPS.length })}
            </p>
            <ThemeToggle variant="icon" />
          </div>
          <div className="h-1 bg-secondary rounded-full overflow-hidden">
            <div
              className="h-full bg-primary transition-all duration-300 rounded-full"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </div>
      </aside>

      {/* ===== Main content ===== */}
      <main className="flex-1 overflow-auto">
        <div className="max-w-2xl mx-auto p-6 md:p-8 min-h-full">
          <StepContent
            step={currentStep}
            onNext={handleNext}
            onPrevious={handlePrevious}
          />
        </div>
      </main>
    </div>
  );
}

interface StepContentProps {
  step: number;
  onNext: () => void;
  onPrevious: () => void;
}

function StepContent({ step, onNext, onPrevious }: StepContentProps) {
  switch (step) {
    case 0:
      return <WelcomeStep onNext={onNext} />;
    case 1:
      return <DatabaseStep onNext={onNext} onPrevious={onPrevious} />;
    // Step ordering swapped (v2.6+), Organization (step 2) is
    // collected BEFORE Admin (step 3) so Admin can submit user + org
    // atomically; see STEPS comment above.
    case 2:
      return <OrganizationStep onNext={onNext} onPrevious={onPrevious} />;
    case 3:
      return <AdminStep onNext={onNext} onPrevious={onPrevious} />;
    case 4:
      return <ModulesStep onNext={onNext} onPrevious={onPrevious} />;
    // Access mode (step 5) sits between Modules and Controllers so the
    // user picks Manage vs Monitor-only before adding controllers.
    case 5:
      return <AccessModeStep onNext={onNext} onPrevious={onPrevious} />;
    case 6:
      return <ControllersStep onNext={onNext} onPrevious={onPrevious} />;
    case 7:
      return <CompleteStep />;
    default:
      return <WelcomeStep onNext={onNext} />;
  }
}
