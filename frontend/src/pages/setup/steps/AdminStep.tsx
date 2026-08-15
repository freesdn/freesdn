// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Setup Wizard: Admin Step
 *
 * Enterprise-grade admin account creation with real-time password
 * strength validation, requirements checklist, and match indicator.
 */
import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { setupApi, type AdminCreateRequest } from '@/lib/setup-api';
import { getApiErrorMessage } from '@/lib/api';
import { useSetupStore } from '@/stores/setupStore';
import { useAuthStore } from '@/stores/authStore';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

import {
  Loader2,
  Shield,
  ChevronRight,
  ChevronLeft,
  Eye,
  EyeOff,
  Check,
  X,
  AlertCircle,
} from 'lucide-react';

/* ------------------------------------------------------------------ */
/*  Password requirements (must match backend app/core/security.py)   */
/* ------------------------------------------------------------------ */

const PASSWORD_RULES = [
  { id: 'length',    labelKey: 'rules.length',  test: (p: string) => p.length >= 12 },
  { id: 'lower',     labelKey: 'rules.lower',   test: (p: string) => /[a-z]/.test(p) },
  { id: 'upper',     labelKey: 'rules.upper',   test: (p: string) => /[A-Z]/.test(p) },
  { id: 'digit',     labelKey: 'rules.digit',   test: (p: string) => /[0-9]/.test(p) },
  { id: 'special',   labelKey: 'rules.special', test: (p: string) => /[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/.test(p) },
] as const;

function getPasswordStrength(password: string): { score: number; labelKey: string; color: string } {
  if (!password) return { score: 0, labelKey: '', color: '' };
  const passed = PASSWORD_RULES.filter(r => r.test(password)).length;
  if (passed <= 1) return { score: 20,  labelKey: 'strength.veryWeak',   color: 'bg-red-500' };
  if (passed === 2) return { score: 40,  labelKey: 'strength.weak',       color: 'bg-red-400' };
  if (passed === 3) return { score: 60,  labelKey: 'strength.fair',       color: 'bg-yellow-500' };
  if (passed === 4) return { score: 80,  labelKey: 'strength.strong',     color: 'bg-green-400' };
  return { score: 100, labelKey: 'strength.veryStrong', color: 'bg-green-500' };
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

interface AdminStepProps {
  onNext: () => void;
  onPrevious: () => void;
}

export function AdminStep({ onNext, onPrevious }: AdminStepProps) {
  const { t } = useTranslation('setup');
  const {
    setAdminInfo,
    setOrganizationInfo,
    organizationName,
    organizationSlug,
  } = useSetupStore();
  const login = useAuthStore((s) => s.login);
  const [submitting, setSubmitting] = useState(false);
  const [showPasswords, setShowPasswords] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [formData, setFormData] = useState<AdminCreateRequest>({
    email: '',
    username: '',
    password: '',
    first_name: '',
    last_name: '',
  });

  const [confirmPassword, setConfirmPassword] = useState('');

  /* -- derived state ------------------------------------------------ */

  const strength = useMemo(() => getPasswordStrength(formData.password), [formData.password]);

  const ruleResults = useMemo(
    () => PASSWORD_RULES.map(r => ({ ...r, passed: r.test(formData.password) })),
    [formData.password],
  );

  const allRulesPassed = ruleResults.every(r => r.passed);

  const passwordsMatch = confirmPassword.length > 0 && formData.password === confirmPassword;
  const passwordsMismatch = confirmPassword.length > 0 && formData.password !== confirmPassword;

  /* -- handlers ----------------------------------------------------- */

  const handleChange = (field: keyof AdminCreateRequest, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    setError(null);
  };

  const validateForm = (): boolean => {
    if (!formData.email) {
      setError(t('AdminStep.errors.emailRequired'));
      return false;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      setError(t('AdminStep.errors.emailInvalid'));
      return false;
    }
    if (!formData.username || formData.username.length < 3) {
      setError(t('AdminStep.errors.usernameTooShort'));
      return false;
    }
    if (!allRulesPassed) {
      setError(t('AdminStep.errors.passwordRequirements'));
      return false;
    }
    if (formData.password !== confirmPassword) {
      setError(t('AdminStep.errors.passwordMismatch'));
      return false;
    }
    return true;
  };

  const handleSubmit = async (e?: React.FormEvent) => {
    e?.preventDefault();

    if (!validateForm()) return;

    setSubmitting(true);
    setError(null);

    try {
      // v2.6+: submit admin + org atomically. Organization fields
      // were collected in the previous wizard step (now step 2) and
      // are still in client state via ``useSetupStore``. The backend
      // creates user + org + default site + membership link in one
      // transaction, without this bundle the admin would be left
      // with ``organization_id=NULL`` and every device-add flow
      // (sites, cameras, phones, hypervisor, PBX) would 422.
      const payload: AdminCreateRequest = {
        ...formData,
        organization_name: organizationName || undefined,
        organization_slug: organizationSlug || undefined,
      };
      const response = await setupApi.createAdmin(payload);
      if (response.success) {
        setAdminInfo(formData.email, formData.username, response.user_id || '');
        if (response.organization_id) {
          setOrganizationInfo(
            organizationName,
            response.organization_slug || organizationSlug,
            response.organization_id,
            response.default_site_id || '',
          );
        }
        // Authenticate the wizard as the just-created super_admin. The setup
        // gate flips to "must be an authenticated super_admin" the moment one
        // exists, so the remaining steps (enable modules, controllers, complete)
        // need a real session. Non-fatal if it fails — the admin still exists
        // and can sign in manually.
        try {
          await login({ login: formData.email, password: formData.password });
        } catch {
          /* auto-login best-effort; manual login remains available */
        }
        onNext();
      } else {
        setError(response.error || t('AdminStep.errors.createFailed'));
      }
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, t('AdminStep.errors.createFailed')));
    } finally {
      setSubmitting(false);
    }
  };

  /* -- render ------------------------------------------------------- */

  return (
    <div className="flex flex-col min-h-full">
      <div className="flex-1 space-y-6">
        <div>
          <h1 className="text-2xl font-bold">{t('AdminStep.title')}</h1>
          <p className="text-muted-foreground mt-1">
            {t('AdminStep.subtitle')}
          </p>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              {t('AdminStep.card.title')}
            </CardTitle>
            <CardDescription>
              {t('AdminStep.card.description')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Info banner */}
              <div className="p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                <p className="text-sm text-blue-600 dark:text-blue-400">
                  <strong>{t('AdminStep.banner.emailLabel')}</strong> {t('AdminStep.banner.text')}
                </p>
              </div>

              {/* Email */}
              <div className="space-y-2">
                <Label htmlFor="email">{t('AdminStep.fields.email.label')}</Label>
                <Input
                  id="email"
                  type="email"
                  placeholder={t('AdminStep.fields.email.placeholder')}
                  autoComplete="email"
                  value={formData.email}
                  onChange={(e) => handleChange('email', e.target.value)}
                  required
                />
                <p className="text-xs text-muted-foreground">
                  {t('AdminStep.fields.email.helper')}
                </p>
              </div>

              {/* Name fields · responsive */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="first_name">{t('AdminStep.fields.firstName.label')}</Label>
                  <Input
                    id="first_name"
                    placeholder="John"
                    autoComplete="given-name"
                    value={formData.first_name}
                    onChange={(e) => handleChange('first_name', e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="last_name">{t('AdminStep.fields.lastName.label')}</Label>
                  <Input
                    id="last_name"
                    placeholder="Doe"
                    autoComplete="family-name"
                    value={formData.last_name}
                    onChange={(e) => handleChange('last_name', e.target.value)}
                  />
                </div>
              </div>

              {/* Username */}
              <div className="space-y-2">
                <Label htmlFor="username">{t('AdminStep.fields.username.label')}</Label>
                <Input
                  id="username"
                  placeholder="admin"
                  autoComplete="username"
                  value={formData.username}
                  onChange={(e) => handleChange('username', e.target.value)}
                  required
                />
                <p className="text-xs text-muted-foreground">
                  {t('AdminStep.fields.username.helper')}
                </p>
              </div>

              {/* ============ Password Section ============ */}
              <div className="space-y-2">
                <Label htmlFor="password">{t('AdminStep.fields.password.label')}</Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPasswords ? 'text' : 'password'}
                    placeholder="••••••••••••"
                    autoComplete="new-password"
                    value={formData.password}
                    onChange={(e) => handleChange('password', e.target.value)}
                    required
                  />
                  <button
                    type="button"
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                    onClick={() => setShowPasswords(v => !v)}
                    tabIndex={-1}
                  >
                    {showPasswords ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>

                {/* Strength meter */}
                {formData.password.length > 0 && (
                  <div className="space-y-2 pt-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-muted-foreground">{t('AdminStep.fields.password.strengthLabel')}</span>
                      <span className={`text-xs font-medium ${
                        strength.score <= 40 ? 'text-red-500'
                        : strength.score <= 60 ? 'text-yellow-500'
                        : 'text-green-500'
                      }`}>
                        {strength.labelKey ? t(`AdminStep.${strength.labelKey}`) : ''}
                      </span>
                    </div>
                    <div className="h-1.5 w-full bg-secondary rounded-full overflow-hidden">
                      <div
                        className={`h-full transition-all duration-300 rounded-full ${strength.color}`}
                        style={{ width: `${strength.score}%` }}
                      />
                    </div>

                    {/* Requirements checklist */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1 pt-1">
                      {ruleResults.map(rule => (
                        <div
                          key={rule.id}
                          className={`flex items-center gap-1.5 text-xs ${
                            rule.passed ? 'text-green-600 dark:text-green-400' : 'text-muted-foreground'
                          }`}
                        >
                          {rule.passed
                            ? <Check className="h-3 w-3 flex-shrink-0" />
                            : <X className="h-3 w-3 flex-shrink-0 opacity-40" />
                          }
                          <span>{t(`AdminStep.${rule.labelKey}`)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* ============ Confirm Password ============ */}
              <div className="space-y-2">
                <Label htmlFor="confirm_password">{t('AdminStep.fields.confirmPassword.label')}</Label>
                <div className="relative">
                  <Input
                    id="confirm_password"
                    type={showPasswords ? 'text' : 'password'}
                    placeholder="••••••••••••"
                    autoComplete="new-password"
                    value={confirmPassword}
                    onChange={(e) => { setConfirmPassword(e.target.value); setError(null); }}
                    required
                  />
                  <button
                    type="button"
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                    onClick={() => setShowPasswords(v => !v)}
                    tabIndex={-1}
                  >
                    {showPasswords ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>

                {/* Match indicator */}
                {passwordsMatch && (
                  <div className="flex items-center gap-1.5 text-xs text-green-600 dark:text-green-400">
                    <Check className="h-3 w-3" />
                    <span>{t('AdminStep.fields.confirmPassword.match')}</span>
                  </div>
                )}
                {passwordsMismatch && (
                  <div className="flex items-center gap-1.5 text-xs text-red-500">
                    <X className="h-3 w-3" />
                    <span>{t('AdminStep.fields.confirmPassword.mismatch')}</span>
                  </div>
                )}
              </div>

              {/* Error display */}
              {error && (
                <div className="flex items-start gap-2 p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
                  <AlertCircle className="h-4 w-4 text-destructive flex-shrink-0 mt-0.5" />
                  <p className="text-destructive text-sm">{error}</p>
                </div>
              )}
            </form>
          </CardContent>
        </Card>
      </div>

      {/* Sticky navigation */}
      <div className="sticky bottom-0 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80 border-t border-border/50 pt-4 pb-4 -mx-1 px-1 mt-6">
        <div className="flex justify-between">
          <Button variant="outline" onClick={onPrevious}>
            <ChevronLeft className="mr-2 h-4 w-4" />
            {t('AdminStep.actions.previous')}
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={submitting || !allRulesPassed || !passwordsMatch}
          >
            {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {t('AdminStep.actions.continue')}
            <ChevronRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}
