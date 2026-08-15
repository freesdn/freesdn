// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '../../stores/authStore';
import { Loader2 } from 'lucide-react';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredPermissions?: string[];
  requireAnyPermission?: boolean;
}

/**
 * ProtectedRoute component for guarding routes that require authentication.
 * 
 * Usage:
 * ```tsx
 * <ProtectedRoute>
 *   <DashboardPage />
 * </ProtectedRoute>
 * 
 * // With permission requirements
 * <ProtectedRoute requiredPermissions={['devices:read']}>
 *   <DevicesPage />
 * </ProtectedRoute>
 * 
 * // Require any of the listed permissions
 * <ProtectedRoute 
 *   requiredPermissions={['users:read', 'users:write']} 
 *   requireAnyPermission
 * >
 *   <UsersPage />
 * </ProtectedRoute>
 * ```
 */
export function ProtectedRoute({
  children,
  requiredPermissions = [],
  requireAnyPermission = false,
}: ProtectedRouteProps) {
  const location = useLocation();
  const { t } = useTranslation('common');
  const { isAuthenticated, isLoading, _isHydrated, _isAuthInitialized, hasAnyPermission, hasAllPermissions, forcePasswordChange } = useAuthStore();

  // Wait for zustand hydration AND initAuth verification before making auth decisions.
  // This prevents the flash of dashboard → /login redirect when tokens are stale.
  if (!_isHydrated || !_isAuthInitialized || isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="text-muted-foreground">{t('ProtectedRoute.loading')}</p>
        </div>
      </div>
    );
  }
  
  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  
  // Redirect to password change if required
  if (forcePasswordChange) {
    return <Navigate to="/change-password" state={{ from: location }} replace />;
  }
  
  // Check permissions if required
  if (requiredPermissions.length > 0) {
    const hasAccess = requireAnyPermission
      ? hasAnyPermission(...requiredPermissions)
      : hasAllPermissions(...requiredPermissions);
    
    if (!hasAccess) {
      return <Navigate to="/unauthorized" state={{ from: location }} replace />;
    }
  }
  
  return <>{children}</>;
}

/**
 * Component to display when user lacks required permissions.
 */
export function UnauthorizedPage() {
  const { t } = useTranslation('common');
  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="text-center space-y-4">
        <div className="text-6xl font-bold text-muted-foreground">403</div>
        <h1 className="text-2xl font-semibold">{t('ProtectedRoute.unauthorized.title')}</h1>
        <p className="text-muted-foreground max-w-md">
          {t('ProtectedRoute.unauthorized.description')}
        </p>
        <div className="flex gap-4 justify-center pt-4">
          <a href="/">
            <button className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
              {t('ProtectedRoute.unauthorized.goToDashboard')}
            </button>
          </a>
          <button
            onClick={() => window.history.back()}
            className="px-4 py-2 border border-border rounded-md hover:bg-muted"
          >
            {t('ProtectedRoute.unauthorized.goBack')}
          </button>
        </div>
      </div>
    </div>
  );
}
