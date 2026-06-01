// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Reset Password Page
 *
 * Consumes a password-reset token from the URL query string and lets
 * the user set a new password.
 *
 * URL format: /reset-password?token=<jwt>
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams, Link } from 'react-router-dom';
import { api, getApiErrorMessage } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent } from '@/components/ui/card';
import {
  Network,
  Loader2,
  AlertCircle,
  Check,
  Eye,
  EyeOff,
  ArrowLeft,
} from 'lucide-react';

export default function ResetPasswordPage() {
  const { t } = useTranslation('auth');
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token') || '';

  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  // NOTE: the backend's
  // validate_password() (see core/security.py) requires a special
  // character when PASSWORD_REQUIRE_SPECIAL is set. Without this check,
  // users would submit a passing-looking password only to receive a
  // backend 400 they couldn't predict. Mirror AdminStep.tsx:37.
  const passwordErrors: string[] = [];
  if (password.length > 0 && password.length < 12)
    passwordErrors.push(t('ResetPasswordPage.passwordRules.minLength'));
  if (password.length > 0 && !/[A-Z]/.test(password))
    passwordErrors.push(t('ResetPasswordPage.passwordRules.uppercase'));
  if (password.length > 0 && !/[a-z]/.test(password))
    passwordErrors.push(t('ResetPasswordPage.passwordRules.lowercase'));
  if (password.length > 0 && !/[0-9]/.test(password))
    passwordErrors.push(t('ResetPasswordPage.passwordRules.number'));
  if (password.length > 0 && !/[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/.test(password))
    passwordErrors.push(t('ResetPasswordPage.passwordRules.special'));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!token) {
      setError(t('ResetPasswordPage.errors.missingToken'));
      return;
    }
    if (password !== confirmPassword) {
      setError(t('ResetPasswordPage.errors.passwordsMismatch'));
      return;
    }
    if (passwordErrors.length > 0) {
      setError(t('ResetPasswordPage.errors.requirementsNotMet'));
      return;
    }

    setIsLoading(true);
    try {
      await api.post('/auth/password/reset', { token, new_password: password });
      setSuccess(true);
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, t('ResetPasswordPage.errors.resetFailed')));
    } finally {
      setIsLoading(false);
    }
  };

  if (success) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted/20 p-4">
        <div className="w-full max-w-md space-y-8">
          <div className="flex flex-col items-center gap-2">
            <div className="flex items-center gap-2">
              <Network className="h-10 w-10 text-primary" />
              <span className="text-3xl font-bold gradient-text">FreeSDN</span>
            </div>
          </div>
          <Card className="border-border/40 shadow-xl">
            <CardContent noOffset>
              <div className="text-center space-y-4">
                <div className="mx-auto w-12 h-12 rounded-full bg-green-500/10 flex items-center justify-center">
                  <Check className="h-6 w-6 text-green-500" />
                </div>
                <h2 className="text-xl font-semibold">{t('ResetPasswordPage.success.heading')}</h2>
                <p className="text-sm text-muted-foreground">
                  {t('ResetPasswordPage.success.description')}
                </p>
                <Link to="/login">
                  <Button className="w-full">{t('ResetPasswordPage.success.goToLogin')}</Button>
                </Link>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted/20 p-4">
      <div className="w-full max-w-md space-y-8">
        <div className="flex flex-col items-center gap-2">
          <div className="flex items-center gap-2">
            <Network className="h-10 w-10 text-primary" />
            <span className="text-3xl font-bold gradient-text">FreeSDN</span>
          </div>
          <p className="text-muted-foreground text-sm">{t('ResetPasswordPage.subtitle')}</p>
        </div>

        <Card className="border-border/40 shadow-xl">
          <CardContent noOffset>
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-2 text-center">
                <h2 className="text-2xl font-semibold tracking-tight">{t('ResetPasswordPage.heading')}</h2>
                <p className="text-sm text-muted-foreground">
                  {t('ResetPasswordPage.formDescription')}
                </p>
              </div>

              {error && (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-destructive/10 text-destructive text-sm">
                  <AlertCircle className="h-4 w-4 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              {!token && (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 text-sm">
                  <AlertCircle className="h-4 w-4 flex-shrink-0" />
                  <span>{t('ResetPasswordPage.noTokenWarning')}</span>
                </div>
              )}

              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="password">{t('ResetPasswordPage.fields.newPassword')}</Label>
                  <div className="relative">
                    <Input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      placeholder="••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete="new-password"
                      required
                      minLength={12}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                  {passwordErrors.length > 0 && (
                    <ul className="text-xs text-muted-foreground list-disc pl-4">
                      {passwordErrors.map((err) => (
                        <li key={err} className="text-destructive">{err}</li>
                      ))}
                    </ul>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="confirmPassword">{t('ResetPasswordPage.fields.confirmPassword')}</Label>
                  <Input
                    id="confirmPassword"
                    type={showPassword ? 'text' : 'password'}
                    placeholder="••••••••"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    autoComplete="new-password"
                    required
                    minLength={12}
                  />
                  {confirmPassword && password !== confirmPassword && (
                    <p className="text-xs text-destructive">{t('ResetPasswordPage.errors.passwordsMismatch')}</p>
                  )}
                </div>
              </div>

              <Button
                type="submit"
                className="w-full"
                disabled={isLoading || !token || password.length < 12 || password !== confirmPassword}
              >
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    {t('ResetPasswordPage.actions.resetting')}
                  </>
                ) : (
                  t('ResetPasswordPage.actions.resetPassword')
                )}
              </Button>

              <div className="text-center">
                <Link to="/login" className="text-sm text-muted-foreground hover:text-primary">
                  <ArrowLeft className="inline h-3 w-3 mr-1" />
                  {t('ResetPasswordPage.actions.backToLogin')}
                </Link>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
