// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '../../stores/authStore';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { api } from '../../lib/api';
import {
  User,
  Mail,
  Building2,
  Shield,
  Key,
  Smartphone,
  LogOut,
  Loader2,
  AlertCircle,
  Check,
  Copy,
} from 'lucide-react';

/**
 * The user record has ONE name column, `full_name`; `first_name`/`last_name`
 * are split out of it by the auth store's normalizeUser. So the form edits the
 * halves and the request has to carry the whole.
 */
function nameFields(user: { first_name?: string; last_name?: string } | null | undefined) {
  return { first_name: user?.first_name || '', last_name: user?.last_name || '' };
}

export function UserProfile() {
  const { t } = useTranslation('common');
  const { user, logout, fetchCurrentUser } = useAuthStore();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Profile form
  const [profile, setProfile] = useState(() => nameFields(user));

  // Re-seed from the server's answer, not from what was typed. Keyed on
  // `full_name` (the only field the backend actually stores) so it fires when a
  // save lands or another session renames the account, and never mid-typing --
  // editing the inputs does not change the store.
  const storedFullName = user?.full_name ?? '';
  useEffect(() => {
    setProfile(nameFields(useAuthStore.getState().user));
  }, [storedFullName]);

  // Password change form
  const [passwordForm, setPasswordForm] = useState({
    current_password: '',
    new_password: '',
    confirm_password: '',
  });
  const [showPasswords, setShowPasswords] = useState(false);
  
  // MFA state
  const [mfaSetup, setMfaSetup] = useState<{
    secret: string;
    qr_code: string;
    backup_codes: string[];
  } | null>(null);
  const [mfaCode, setMfaCode] = useState('');
  // POST /auth/mfa/disable takes a REQUIRED `password` body field (step-up
  // re-auth). This used to post no body at all, so FastAPI rejected it with a
  // 422 before the handler ran and MFA could never be turned off from the UI —
  // the toast just said "Failed to disable MFA". Collect the password first.
  const [showDisableMfa, setShowDisableMfa] = useState(false);
  const [disableMfaPassword, setDisableMfaPassword] = useState('');

  const handleProfileUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setIsLoading(true);
    
    try {
      // PATCH /auth/me is validated by ProfileUpdateRequest, which declares
      // full_name / username / language and (like every schema here) does not
      // forbid extras. This used to send `{first_name, last_name}`: pydantic
      // dropped both, the handler committed an empty update, the endpoint
      // answered 200 and the UI reported "profile updated" while nothing had
      // changed -- the old name was still there on reload. There is no
      // first_name column to write; core.users has full_name.
      const full_name = [profile.first_name.trim(), profile.last_name.trim()]
        .filter(Boolean)
        .join(' ');
      await api.patch('/auth/me', { full_name });
      await fetchCurrentUser();
      setSuccess(t('UserProfile.messages.profileUpdated'));
    } catch (err: unknown) {
      const axiosErr = err as import('axios').AxiosError<{ detail?: string }>;
      setError(axiosErr.response?.data?.detail || t('UserProfile.messages.profileUpdateFailed'));
    } finally {
      setIsLoading(false);
    }
  };
  
  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    
    if (passwordForm.new_password !== passwordForm.confirm_password) {
      setError(t('UserProfile.messages.passwordsDoNotMatch'));
      return;
    }
    
    setIsLoading(true);
    
    try {
      await api.post('/auth/password', {
        current_password: passwordForm.current_password,
        new_password: passwordForm.new_password,
      });
      setSuccess(t('UserProfile.messages.passwordChanged'));
      setPasswordForm({
        current_password: '',
        new_password: '',
        confirm_password: '',
      });
    } catch (err: unknown) {
      const axiosErr = err as import('axios').AxiosError<{ detail?: string }>;
      setError(axiosErr.response?.data?.detail || t('UserProfile.messages.passwordChangeFailed'));
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleEnableMfa = async () => {
    setError(null);
    setIsLoading(true);
    
    try {
      const response = await api.post('/auth/mfa/setup');
      setMfaSetup(response.data);
    } catch (err: unknown) {
      const axiosErr = err as import('axios').AxiosError<{ detail?: string }>;
      setError(axiosErr.response?.data?.detail || t('UserProfile.messages.mfaSetupFailed'));
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleConfirmMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);
    
    try {
      await api.post('/auth/mfa/enable', { code: mfaCode });
      await fetchCurrentUser();
      setSuccess(t('UserProfile.messages.mfaEnabled'));
      setMfaSetup(null);
      setMfaCode('');
    } catch (err: unknown) {
      const axiosErr = err as import('axios').AxiosError<{ detail?: string }>;
      setError(axiosErr.response?.data?.detail || t('UserProfile.messages.mfaInvalidCode'));
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleDisableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setIsLoading(true);

    try {
      await api.post('/auth/mfa/disable', { password: disableMfaPassword });
      await fetchCurrentUser();
      setSuccess(t('UserProfile.messages.mfaDisabled'));
      setShowDisableMfa(false);
      setDisableMfaPassword('');
    } catch (err: unknown) {
      const axiosErr = err as import('axios').AxiosError<{ detail?: string }>;
      setError(axiosErr.response?.data?.detail || t('UserProfile.messages.mfaDisableFailed'));
    } finally {
      setIsLoading(false);
    }
  };
  
  if (!user) return null;
  
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{t('UserProfile.header.title')}</h1>
          <p className="text-muted-foreground">{t('UserProfile.header.subtitle')}</p>
        </div>
        <Button variant="destructive" onClick={logout}>
          <LogOut className="mr-2 h-4 w-4" />
          {t('UserProfile.actions.signOut')}
        </Button>
      </div>
      
      {/* Messages */}
      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-destructive/10 text-destructive text-sm">
          <AlertCircle className="h-4 w-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}
      
      {success && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-green-500/10 text-green-500 text-sm">
          <Check className="h-4 w-4 flex-shrink-0" />
          <span>{success}</span>
        </div>
      )}
      
      <div className="grid gap-6 md:grid-cols-2">
        {/* Profile Information */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <User className="h-5 w-5" />
              {t('UserProfile.profile.title')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleProfileUpdate} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email">{t('UserProfile.profile.email')}</Label>
                <div className="flex items-center gap-2">
                  <Mail className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm">{user.email}</span>
                </div>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="first_name">{t('UserProfile.profile.firstName')}</Label>
                  <Input
                    id="first_name"
                    value={profile.first_name}
                    onChange={(e) => setProfile({ ...profile, first_name: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="last_name">{t('UserProfile.profile.lastName')}</Label>
                  <Input
                    id="last_name"
                    value={profile.last_name}
                    onChange={(e) => setProfile({ ...profile, last_name: e.target.value })}
                  />
                </div>
              </div>
              
              <div className="space-y-2">
                <Label>{t('UserProfile.profile.organization')}</Label>
                <div className="flex items-center gap-2">
                  <Building2 className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm">{user.organization_id || t('UserProfile.profile.none')}</span>
                </div>
              </div>
              
              <div className="space-y-2">
                <Label>{t('UserProfile.profile.roles')}</Label>
                <div className="flex flex-wrap gap-2">
                  {(user.roles ?? []).map((role) => (
                    <span
                      key={role}
                      className="px-2 py-1 bg-primary/10 text-primary text-xs rounded-full"
                    >
                      {role}
                    </span>
                  ))}
                </div>
              </div>
              
              <Button type="submit" disabled={isLoading}>
                {isLoading ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : null}
                {t('UserProfile.actions.saveChanges')}
              </Button>
            </form>
          </CardContent>
        </Card>
        
        {/* Change Password */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" />
              {t('UserProfile.password.title')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handlePasswordChange} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="current_password">{t('UserProfile.password.current')}</Label>
                <div className="relative">
                  <Input
                    id="current_password"
                    type={showPasswords ? 'text' : 'password'}
                    value={passwordForm.current_password}
                    onChange={(e) => setPasswordForm({ ...passwordForm, current_password: e.target.value })}
                    required
                  />
                </div>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="new_password">{t('UserProfile.password.new')}</Label>
                <div className="relative">
                  <Input
                    id="new_password"
                    type={showPasswords ? 'text' : 'password'}
                    value={passwordForm.new_password}
                    onChange={(e) => setPasswordForm({ ...passwordForm, new_password: e.target.value })}
                    required
                  />
                </div>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="confirm_password">{t('UserProfile.password.confirm')}</Label>
                <div className="relative">
                  <Input
                    id="confirm_password"
                    type={showPasswords ? 'text' : 'password'}
                    value={passwordForm.confirm_password}
                    onChange={(e) => setPasswordForm({ ...passwordForm, confirm_password: e.target.value })}
                    required
                  />
                </div>
              </div>
              
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="show_passwords"
                  checked={showPasswords}
                  onChange={(e) => setShowPasswords(e.target.checked)}
                  className="rounded"
                />
                <Label htmlFor="show_passwords" className="text-sm font-normal cursor-pointer">
                  {t('UserProfile.password.showPasswords')}
                </Label>
              </div>
              
              <Button type="submit" disabled={isLoading}>
                {isLoading ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : null}
                {t('UserProfile.password.title')}
              </Button>
            </form>
          </CardContent>
        </Card>
        
        {/* Two-Factor Authentication */}
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              {t('UserProfile.mfa.title')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {mfaSetup ? (
              <div className="space-y-4">
                <p className="text-sm text-muted-foreground">
                  {t('UserProfile.mfa.scanInstructions')}
                </p>
                
                <div className="flex flex-col md:flex-row gap-6 items-start">
                  <div className="p-4 bg-white rounded-lg">
                    <img src={mfaSetup.qr_code} alt={t('UserProfile.mfa.qrCodeAlt')} className="w-48 h-48" />
                  </div>
                  
                  <div className="flex-1 space-y-4">
                    <div>
                      <Label className="text-xs text-muted-foreground">{t('UserProfile.mfa.manualEntryKey')}</Label>
                      <div className="flex items-center gap-2 mt-1">
                        <code className="px-2 py-1 bg-muted rounded text-sm font-mono">
                          {mfaSetup.secret}
                        </code>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => navigator.clipboard.writeText(mfaSetup.secret)}
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                    
                    <div>
                      <Label className="text-xs text-muted-foreground">{t('UserProfile.mfa.backupCodes')}</Label>
                      <div className="grid grid-cols-2 gap-2 mt-1">
                        {mfaSetup.backup_codes.map((code, i) => (
                          <code key={i} className="px-2 py-1 bg-muted rounded text-sm font-mono text-center">
                            {code}
                          </code>
                        ))}
                      </div>
                    </div>
                    
                    <form onSubmit={handleConfirmMfa} className="space-y-2">
                      <Label htmlFor="mfa_code">{t('UserProfile.mfa.enterCode')}</Label>
                      <div className="flex gap-2">
                        <Input
                          id="mfa_code"
                          type="text"
                          inputMode="numeric"
                          pattern="[0-9]*"
                          maxLength={6}
                          placeholder="000000"
                          value={mfaCode}
                          onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                          className="w-32 text-center font-mono"
                        />
                        <Button type="submit" disabled={isLoading || mfaCode.length !== 6}>
                          {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : t('UserProfile.mfa.verifyEnable')}
                        </Button>
                        <Button type="button" variant="outline" onClick={() => setMfaSetup(null)}>
                          {t('UserProfile.actions.cancel')}
                        </Button>
                      </div>
                    </form>
                  </div>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <Smartphone className="h-8 w-8 text-muted-foreground" />
                    <div>
                      <p className="font-medium">
                        {user.mfa_enabled ? t('UserProfile.mfa.statusEnabled') : t('UserProfile.mfa.statusDisabled')}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        {user.mfa_enabled
                          ? t('UserProfile.mfa.statusEnabledDescription')
                          : t('UserProfile.mfa.statusDisabledDescription')}
                      </p>
                    </div>
                  </div>

                  {user.mfa_enabled ? (
                    <Button
                      type="button"
                      variant="destructive"
                      onClick={() => setShowDisableMfa(true)}
                      disabled={isLoading || showDisableMfa}
                    >
                      {t('UserProfile.mfa.disable')}
                    </Button>
                  ) : (
                    <Button onClick={handleEnableMfa} disabled={isLoading}>
                      {isLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                      {t('UserProfile.mfa.enable')}
                    </Button>
                  )}
                </div>

                {/* Step-up re-auth: /auth/mfa/disable requires the account
                    password, so there has to be somewhere to type it. */}
                {user.mfa_enabled && showDisableMfa && (
                  <form onSubmit={handleDisableMfa} className="space-y-2 max-w-md">
                    <Label htmlFor="disable_mfa_password">{t('UserProfile.password.current')}</Label>
                    <div className="flex gap-2">
                      <Input
                        id="disable_mfa_password"
                        type="password"
                        autoComplete="current-password"
                        value={disableMfaPassword}
                        onChange={(e) => setDisableMfaPassword(e.target.value)}
                        required
                      />
                      <Button
                        type="submit"
                        variant="destructive"
                        disabled={isLoading || !disableMfaPassword}
                      >
                        {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : t('UserProfile.mfa.disable')}
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => {
                          setShowDisableMfa(false);
                          setDisableMfaPassword('');
                        }}
                      >
                        {t('UserProfile.actions.cancel')}
                      </Button>
                    </div>
                  </form>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
