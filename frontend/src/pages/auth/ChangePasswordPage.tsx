// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Change Password Page
 *
 * Shown when `forcePasswordChange` is true in the auth store
 * (e.g. first login after an admin reset, or password-rotation policy).
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '@/stores/authStore';
import { api, getApiErrorMessage } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent } from '@/components/ui/card';
import { Network, Loader2, AlertCircle, Eye, EyeOff, ShieldAlert } from 'lucide-react';

export default function ChangePasswordPage() {
  const { t } = useTranslation('auth');
  const navigate = useNavigate();
  const { clearForcePasswordChange } = useAuthStore();

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // NOTE: backend validate_password()
  // requires a special character. Mirror AdminStep.tsx:37 so the user
  // can't submit and get a backend 400.
  const passwordErrors: string[] = [];
  if (newPassword.length > 0 && newPassword.length < 12) passwordErrors.push(t('ChangePasswordPage.requirements.minLength'));
  if (newPassword.length > 0 && !/[A-Z]/.test(newPassword)) passwordErrors.push(t('ChangePasswordPage.requirements.uppercase'));
  if (newPassword.length > 0 && !/[a-z]/.test(newPassword)) passwordErrors.push(t('ChangePasswordPage.requirements.lowercase'));
  if (newPassword.length > 0 && !/[0-9]/.test(newPassword)) passwordErrors.push(t('ChangePasswordPage.requirements.number'));
  if (newPassword.length > 0 && !/[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/.test(newPassword))
    passwordErrors.push(t('ChangePasswordPage.requirements.specialChar'));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (newPassword !== confirmPassword) {
      setError(t('ChangePasswordPage.errors.mismatch'));
      return;
    }
    if (passwordErrors.length > 0) {
      setError(t('ChangePasswordPage.errors.requirementsNotMet'));
      return;
    }

    setIsLoading(true);
    try {
      await api.post('/auth/password', {
        current_password: currentPassword,
        new_password: newPassword,
      });
      clearForcePasswordChange();
      navigate('/dashboard', { replace: true });
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, t('ChangePasswordPage.errors.changeFailed')));
    } finally {
      setIsLoading(false);
    }
  };

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
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="flex justify-center mb-2">
                <div className="p-3 rounded-full bg-amber-500/10">
                  <ShieldAlert className="h-7 w-7 text-amber-500" />
                </div>
              </div>
              <div className="space-y-2 text-center">
                <h2 className="text-2xl font-semibold tracking-tight">{t('ChangePasswordPage.heading')}</h2>
                <p className="text-sm text-muted-foreground">
                  {t('ChangePasswordPage.subheading')}
                </p>
              </div>

              {error && (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-destructive/10 text-destructive text-sm">
                  <AlertCircle className="h-4 w-4 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="currentPassword">{t('ChangePasswordPage.fields.currentPassword')}</Label>
                  <Input
                    id="currentPassword"
                    type={showPassword ? 'text' : 'password'}
                    placeholder="••••••••"
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    autoComplete="current-password"
                    autoFocus
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="newPassword">{t('ChangePasswordPage.fields.newPassword')}</Label>
                  <div className="relative">
                    <Input
                      id="newPassword"
                      type={showPassword ? 'text' : 'password'}
                      placeholder="••••••••"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
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
                  <Label htmlFor="confirmNewPassword">{t('ChangePasswordPage.fields.confirmNewPassword')}</Label>
                  <Input
                    id="confirmNewPassword"
                    type={showPassword ? 'text' : 'password'}
                    placeholder="••••••••"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    autoComplete="new-password"
                    required
                    minLength={12}
                  />
                  {confirmPassword && newPassword !== confirmPassword && (
                    <p className="text-xs text-destructive">{t('ChangePasswordPage.errors.mismatch')}</p>
                  )}
                </div>
              </div>

              <Button
                type="submit"
                className="w-full"
                disabled={isLoading || newPassword.length < 12 || newPassword !== confirmPassword}
              >
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    {t('ChangePasswordPage.actions.changing')}
                  </>
                ) : (
                  t('ChangePasswordPage.actions.changePassword')
                )}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
