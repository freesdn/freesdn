// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Module Guard
 * 
 * Route guard component that checks whether a module is enabled
 * before rendering its content. Shows a "Module Disabled" page
 * if the module is not enabled for the current organization.
 */
import { type ReactNode } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Settings,
  ArrowLeft,
  ShieldOff,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { useModuleStore, type ModuleManifest } from '@/stores/moduleStore';

interface ModuleGuardProps {
  moduleId: string;
  children: ReactNode;
  /** If true, silently redirect to dashboard instead of showing disabled page */
  redirect?: boolean;
}

/**
 * Wraps module routes to enforce module enablement.
 * If the module is not enabled, shows a "Module Disabled" UI
 * with a link to Settings > Modules to enable it.
 */
export function ModuleGuard({ moduleId, children, redirect = false }: ModuleGuardProps) {
  const { isModuleEnabled, isLoaded, getModule } = useModuleStore();

  // Until module enablement is actually known (isLoaded), render children
  // optimistically so an enabled module never flashes a false "module not
  // enabled" while the org-enablement query is still resolving. enabledModules
  // is loaded fresh from the API each session (never persisted — see
  // moduleStore), and isLoaded only flips once that enablement has resolved
  // (see useModulesInit). The backend enforces real module access, so this
  // optimistic render is UX-only.
  if (!isLoaded) {
    return <>{children}</>;
  }

  const enabled = isModuleEnabled(moduleId);

  if (enabled) {
    return <>{children}</>;
  }

  if (redirect) {
    return <Navigate to="/" replace />;
  }

  const module = getModule(moduleId);
  return <ModuleDisabledPage moduleId={moduleId} module={module} />;
}

// ────────────────────────────────────────────────────────────
// Module Disabled Page
// ────────────────────────────────────────────────────────────

function ModuleDisabledPage({
  moduleId,
  module,
}: {
  moduleId: string;
  module?: ModuleManifest;
}) {
  const navigate = useNavigate();
  const { t } = useTranslation('common');

  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <Card className="max-w-md w-full">
        <CardContent noOffset className="text-center space-y-6">
          {/* Icon */}
          <div className="flex justify-center">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-muted">
              <ShieldOff className="h-8 w-8 text-muted-foreground" />
            </div>
          </div>

          {/* Title */}
          <div className="space-y-2">
            <h2 className="text-xl font-semibold">{t('ModuleGuard.title')}</h2>
            <p className="text-sm text-muted-foreground">
              {t('ModuleGuard.disabledMessage.before')}{' '}
              <span className="font-medium text-foreground">{module?.name || moduleId}</span>{' '}
              {t('ModuleGuard.disabledMessage.after')}
            </p>
            {module?.description && (
              <p className="text-xs text-muted-foreground mt-1">
                {module.description}
              </p>
            )}
          </div>

          {/* Actions */}
          <div className="flex flex-col gap-2">
            <Button
              onClick={() => navigate('/settings/modules')}
              className="w-full"
            >
              <Settings className="mr-2 h-4 w-4" />
              {t('ModuleGuard.actions.goToSettings')}
            </Button>
            <Button
              variant="outline"
              onClick={() => navigate(-1)}
              className="w-full"
            >
              <ArrowLeft className="mr-2 h-4 w-4" />
              {t('ModuleGuard.actions.goBack')}
            </Button>
          </div>

          {/* Help text */}
          <p className="text-xs text-muted-foreground">
            {t('ModuleGuard.helpText')}
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

export default ModuleGuard;
