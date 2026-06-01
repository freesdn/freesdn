// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Login Page
 * 
 * Full-featured login with:
 * - Email/password authentication
 * - MFA support (TOTP)
 * - Form validation
 * - Remember me option
 * - Password visibility toggle
 */

import { useState, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import type { TFunction } from 'i18next';
import { useAuthStore } from '@/stores/authStore';
import { setupApi } from '@/lib/setup-api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { 
  Loader2, 
  AlertCircle, 
  Eye, 
  EyeOff, 
  Shield,
  Lock,
  User,
} from 'lucide-react';
import SSOLoginButtons from '@/components/auth/SSOLoginButtons';

// Login form schema
// NOTE: removed `rememberMe`, the checkbox was never wired to
// the backend and was a dark-pattern as-is. TODO: if/when product wants
// this back, the FE must send `remember_me: true` to /auth/login and the
// backend must honor it by extending the refresh-cookie max_age.
const makeLoginSchema = (t: TFunction) =>
  z.object({
    login: z.string().min(1, t('LoginPage.validation.loginRequired')),
    password: z.string().min(1, t('LoginPage.validation.passwordRequired')),
  });

// MFA form schema
const makeMfaSchema = (t: TFunction) =>
  z.object({
    code: z
      .string()
      .length(6, t('LoginPage.validation.mfaLength'))
      .regex(/^\d+$/, t('LoginPage.validation.mfaNumeric')),
  });

type LoginFormData = z.infer<ReturnType<typeof makeLoginSchema>>;
type MfaFormData = z.infer<ReturnType<typeof makeMfaSchema>>;

export function LoginPage() {
  const { t } = useTranslation('auth');
  const loginSchema = useMemo(() => makeLoginSchema(t), [t]);
  const mfaSchema = useMemo(() => makeMfaSchema(t), [t]);
  const [showPassword, setShowPassword] = useState(false);
  const [showMfa, setShowMfa] = useState(false);
  const [ssoError, setSsoError] = useState<string | null>(null);
  const navigate = useNavigate();
  const location = useLocation();
  const { login, verifyMfa, isLoading, mfaPending, error, clearError } = useAuthStore();

  // Get redirect URL from location state
  const from = (location.state as { from?: Location })?.from?.pathname || '/dashboard';

  // Redirect to setup wizard if setup is not complete
  useEffect(() => {
    setupApi.getStatus()
      .then((status) => {
        if (!status.is_complete) {
          navigate('/setup', { replace: true });
        }
      })
      .catch(() => {
        // If setup API fails, let user attempt login normally
      });
  }, [navigate]);

  // Login form
  const loginForm = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      login: '',
      password: '',
    },
  });

  // MFA form
  const mfaForm = useForm<MfaFormData>({
    resolver: zodResolver(mfaSchema),
    defaultValues: {
      code: '',
    },
  });

  // Handle login submit
  const handleLogin = async (data: LoginFormData) => {
    clearError();
    
    try {
      const result = await login({ login: data.login, password: data.password });
      
      if (result.mfaRequired) {
        setShowMfa(true);
      } else if (result.success) {
        navigate(from, { replace: true });
      }
    } catch {
      // Error is handled by the store
    }
  };

  // Handle MFA submit
  const handleMfa = async (data: MfaFormData) => {
    clearError();
    const mfaToken = useAuthStore.getState().mfaToken;
    
    try {
      const success = await verifyMfa({ mfa_token: mfaToken || '', code: data.code });
      if (success) {
        navigate(from, { replace: true });
      }
    } catch {
      // Error is handled by the store
    }
  };

  // MFA Input form
  if (showMfa || mfaPending) {
    return (
      <div className="w-full max-w-md">
        <div className="rounded-lg bg-white p-8 shadow-xl dark:bg-slate-800">
          {/* Header */}
          <div className="mb-6 text-center">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
              <Shield className="h-6 w-6 text-primary" />
            </div>
            <h2 className="text-2xl font-semibold text-slate-900 dark:text-white">
              {t('LoginPage.mfa.title')}
            </h2>
            <p className="mt-2 text-sm text-muted-foreground">
              {t('LoginPage.mfa.subtitle')}
            </p>
          </div>

          {/* Error message */}
          {error && (
            <div className="mb-4 flex items-center gap-2 rounded-lg bg-destructive/10 border border-destructive/20 p-3 text-sm text-destructive">
              <AlertCircle className="h-4 w-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* MFA Form */}
          <form onSubmit={mfaForm.handleSubmit(handleMfa)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="code">{t('LoginPage.mfa.codeLabel')}</Label>
              <Input
                id="code"
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                placeholder="000000"
                className="text-center text-2xl tracking-widest"
                {...mfaForm.register('code')}
                autoFocus
              />
              {mfaForm.formState.errors.code && (
                <p className="text-sm text-red-600">{mfaForm.formState.errors.code.message}</p>
              )}
            </div>

            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {t('LoginPage.mfa.verify')}
            </Button>

            <Button
              type="button"
              variant="ghost"
              className="w-full"
              onClick={() => {
                setShowMfa(false);
                clearError();
              }}
            >
              {t('LoginPage.mfa.backToLogin')}
            </Button>
          </form>
        </div>
      </div>
    );
  }

  // Login form
  return (
    <div className="w-full max-w-md">
      <div className="rounded-lg bg-white p-8 shadow-xl dark:bg-slate-800">
        {/* Header */}
        <div className="mb-6 text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
            <Lock className="h-6 w-6 text-primary" />
          </div>
          <h2 className="text-2xl font-semibold text-slate-900 dark:text-white">
            {t('LoginPage.title')}
          </h2>
          <p className="mt-2 text-sm text-muted-foreground">
            {t('LoginPage.subtitle')}
          </p>
        </div>

        {/* Error message */}
        {error && (
          <div className="mb-4 flex items-center gap-2 rounded-lg bg-destructive/10 border border-destructive/20 p-3 text-sm text-destructive">
            <AlertCircle className="h-4 w-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}
        {ssoError && (
          <div className="mb-4 flex items-center gap-2 rounded-lg bg-destructive/10 border border-destructive/20 p-3 text-sm text-destructive">
            <AlertCircle className="h-4 w-4 flex-shrink-0" />
            <span>{ssoError}</span>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={loginForm.handleSubmit(handleLogin)} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="login">{t('LoginPage.fields.login.label')}</Label>
            <div className="relative">
              <User className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                id="login"
                type="text"
                placeholder={t('LoginPage.fields.login.placeholder')}
                className="pl-10"
                {...loginForm.register('login')}
                autoComplete="username"
                autoFocus
              />
            </div>
            {loginForm.formState.errors.login && (
              <p className="text-sm text-red-600">{loginForm.formState.errors.login.message}</p>
            )}
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label htmlFor="password">{t('LoginPage.fields.password.label')}</Label>
              <Link
                to="/forgot-password"
                className="text-xs text-primary hover:underline"
              >
                {t('LoginPage.forgotPassword')}
              </Link>
            </div>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                id="password"
                type={showPassword ? 'text' : 'password'}
                placeholder="••••••••"
                className="pl-10 pr-10"
                {...loginForm.register('password')}
                autoComplete="current-password"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              >
                {showPassword ? (
                  <EyeOff className="h-4 w-4" />
                ) : (
                  <Eye className="h-4 w-4" />
                )}
              </button>
            </div>
            {loginForm.formState.errors.password && (
              <p className="text-sm text-red-600">{loginForm.formState.errors.password.message}</p>
            )}
          </div>

          {/* NOTE: removed "Remember me" checkbox, was never wired
              to the backend. See loginSchema comment above. */}

          <Button type="submit" className="w-full" disabled={isLoading}>
            {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {t('LoginPage.signIn')}
          </Button>
        </form>

        {/* SSO Providers */}
        <SSOLoginButtons onError={(msg) => setSsoError(msg)} />

        {/* Footer */}
        <div className="mt-6 text-center text-sm text-muted-foreground">
          <p>
            {t('LoginPage.footer.tagline')}
          </p>
        </div>
      </div>
    </div>
  );
}
