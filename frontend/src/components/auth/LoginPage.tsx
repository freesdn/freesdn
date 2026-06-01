// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useLocation, Navigate, Link } from 'react-router-dom';
import { useAuthStore } from '../../stores/authStore';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Card, CardContent } from '../ui/card';
import { Network, Eye, EyeOff, Loader2, AlertCircle, Shield } from 'lucide-react';
import { isDemoMode } from '@/demo/mode';

export function LoginPage() {
  const { t } = useTranslation('common');
  const navigate = useNavigate();
  const location = useLocation();
  const { login, verifyMfa, isLoading, error, mfaPending, mfaToken, clearError, isAuthenticated, _isHydrated, _isAuthInitialized } = useAuthStore();
  
  const [loginInput, setLoginInput] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [mfaCode, setMfaCode] = useState('');
  const [checkingSetup, setCheckingSetup] = useState(true);
  
  // Get redirect path from location state
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const from = (location.state as any)?.from?.pathname || '/';

  // Check if setup is needed · redirect to /setup on fresh install
  useEffect(() => {
    const checkSetup = async () => {
      // Demo build: no backend, setup is always "complete", skip the probe so
      // the static demo makes zero same-origin /api/v1 calls.
      if (isDemoMode) {
        setCheckingSetup(false);
        return;
      }
      try {
        const res = await fetch('/api/v1/setup/status');
        if (res.ok) {
          const data = await res.json();
          if (!data.is_complete) {
            navigate('/setup', { replace: true });
            return;
          }
        }
      } catch {
        // backend unreachable · just show login
      } finally {
        setCheckingSetup(false);
      }
    };
    checkSetup();
  }, [navigate]);
  
  // If already authenticated (verified by initAuth), redirect away from login
  if (_isAuthInitialized && isAuthenticated) {
    return <Navigate to={from} replace />;
  }

  // Wait for zustand hydration AND initAuth verification before showing login form.
  if (!_isHydrated || !_isAuthInitialized || checkingSetup) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      </div>
    );
  }

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();
    
    const result = await login({ login: loginInput, password, rememberMe });
    
    if (result.success && !result.mfaRequired) {
      navigate(from, { replace: true });
    }
  };
  
  const handleMfaVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();
    
    if (!mfaToken) return;
    
    const success = await verifyMfa({ mfa_token: mfaToken, code: mfaCode });
    
    if (success) {
      navigate(from, { replace: true });
    }
  };
  
  // MFA Verification Form
  if (mfaPending) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted/20 p-4">
        <div className="w-full max-w-md space-y-8">
          {/* Logo */}
          <div className="flex flex-col items-center gap-2">
            <div className="flex items-center gap-2">
              <Network className="h-10 w-10 text-primary" />
              <span className="text-3xl font-bold gradient-text">FreeSDN</span>
            </div>
            <p className="text-muted-foreground text-sm">{t('LoginPageComponent.mfa.subtitle')}</p>
          </div>
          
          <Card className="border-border/40 shadow-xl">
            <CardContent noOffset>
              <form onSubmit={handleMfaVerify} className="space-y-6">
                <div className="flex justify-center mb-4">
                  <div className="p-4 rounded-full bg-primary/10">
                    <Shield className="h-8 w-8 text-primary" />
                  </div>
                </div>
                
                <div className="text-center space-y-2">
                  <h2 className="text-xl font-semibold">{t('LoginPageComponent.mfa.heading')}</h2>
                  <p className="text-sm text-muted-foreground">
                    {t('LoginPageComponent.mfa.instructions')}
                  </p>
                </div>
                
                {error && (
                  <div className="flex items-center gap-2 p-3 rounded-lg bg-destructive/10 text-destructive text-sm">
                    <AlertCircle className="h-4 w-4 flex-shrink-0" />
                    <span>{typeof error === 'string' ? error : t('LoginPageComponent.errors.generic')}</span>
                  </div>
                )}
                
                <div className="space-y-2">
                  <Label htmlFor="mfaCode">{t('LoginPageComponent.mfa.codeLabel')}</Label>
                  <Input
                    id="mfaCode"
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength={6}
                    placeholder="000000"
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                    className="text-center text-2xl tracking-widest font-mono"
                    autoFocus
                    required
                  />
                </div>
                
                <Button type="submit" className="w-full" disabled={isLoading || mfaCode.length !== 6}>
                  {isLoading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      {t('LoginPageComponent.mfa.verifying')}
                    </>
                  ) : (
                    t('LoginPageComponent.mfa.verifyButton')
                  )}
                </Button>
                
                <div className="text-center">
                  <button
                    type="button"
                    onClick={() => {
                      clearError();
                      setMfaCode('');
                      // Reset to login form
                      window.location.reload();
                    }}
                    className="text-sm text-muted-foreground hover:text-primary transition-colors"
                  >
                    {t('LoginPageComponent.mfa.backToLogin')}
                  </button>
                </div>
              </form>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }
  
  // Login Form
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted/20 p-4">
      <div className="w-full max-w-md space-y-8">
        {/* Logo */}
        <div className="flex flex-col items-center gap-2">
          <div className="flex items-center gap-2">
            <Network className="h-10 w-10 text-primary" />
            <span className="text-3xl font-bold gradient-text">FreeSDN</span>
          </div>
          <p className="text-muted-foreground text-sm">
            {t('LoginPageComponent.tagline')}
          </p>
        </div>
        
        <Card className="border-border/40 shadow-xl">
          <CardContent noOffset>
            <form onSubmit={handleLogin} className="space-y-6">
              <div className="space-y-2 text-center">
                <h2 className="text-2xl font-semibold tracking-tight">{t('LoginPageComponent.login.heading')}</h2>
                <p className="text-sm text-muted-foreground">
                  {t('LoginPageComponent.login.subtitle')}
                </p>
              </div>
              
              {error && (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-destructive/10 text-destructive text-sm">
                  <AlertCircle className="h-4 w-4 flex-shrink-0" />
                  <span>{typeof error === 'string' ? error : t('LoginPageComponent.errors.generic')}</span>
                </div>
              )}
              
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="login">{t('LoginPageComponent.login.identifierLabel')}</Label>
                  <Input
                    id="login"
                    type="text"
                    placeholder={t('LoginPageComponent.login.identifierPlaceholder')}
                    value={loginInput}
                    onChange={(e) => setLoginInput(e.target.value)}
                    autoComplete="username"
                    autoFocus
                    required
                  />
                </div>
                
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="password">{t('LoginPageComponent.login.passwordLabel')}</Label>
                    <Link
                      to="/forgot-password"
                      className="text-xs text-muted-foreground hover:text-primary transition-colors"
                    >
                      {t('LoginPageComponent.login.forgotPassword')}
                    </Link>
                  </div>
                  <div className="relative">
                    <Input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      placeholder="••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete="current-password"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                      aria-label={showPassword ? t('LoginPageComponent.login.hidePassword') : t('LoginPageComponent.login.showPassword')}
                    >
                      {showPassword ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Remember me — opts into the extended (30-day) session window. */}
                <label
                  htmlFor="rememberMe"
                  className="flex items-center gap-2 text-sm text-muted-foreground cursor-pointer select-none"
                >
                  <input
                    id="rememberMe"
                    type="checkbox"
                    className="h-4 w-4 rounded border-input accent-primary"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                  />
                  {t('LoginPageComponent.login.rememberMe')}
                </label>
              </div>

              <Button type="submit" className="w-full" disabled={isLoading}>
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    {t('LoginPageComponent.login.signingIn')}
                  </>
                ) : (
                  t('LoginPageComponent.login.signIn')
                )}
              </Button>
              
              <div className="text-center text-sm">
                <span className="text-muted-foreground">{t('LoginPageComponent.login.noAccount')} </span>
                <Link to="/register" className="text-primary hover:underline font-medium">
                  {t('LoginPageComponent.login.requestAccess')}
                </Link>
              </div>
            </form>
          </CardContent>
        </Card>
        
        {/* Footer */}
        <p className="text-center text-xs text-muted-foreground">
          {t('LoginPageComponent.footer.agreePrefix')}{' '}
          <a href="#" className="hover:text-primary transition-colors">{t('LoginPageComponent.footer.termsOfService')}</a>
          {' '}{t('LoginPageComponent.footer.and')}{' '}
          <a href="#" className="hover:text-primary transition-colors">{t('LoginPageComponent.footer.privacyPolicy')}</a>
        </p>
      </div>
    </div>
  );
}
