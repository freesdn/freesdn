// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation, Trans } from 'react-i18next';
import { api } from '../../lib/api';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Card, CardContent } from '../ui/card';
import { Network, Loader2, AlertCircle, Check, ArrowLeft } from 'lucide-react';

export function ForgotPasswordPage() {
  const { t } = useTranslation('common');
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);
    
    try {
      await api.post('/auth/password/reset-request', { email });
      setSuccess(true);
    } catch (_err: unknown) {
      // Don't reveal if email exists or not
      setSuccess(true);
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
                <h2 className="text-xl font-semibold">{t('ForgotPasswordPage.success.title')}</h2>
                <p className="text-sm text-muted-foreground">
                  <Trans
                    i18nKey="ForgotPasswordPage.success.description"
                    ns="common"
                    values={{ email }}
                    components={{ strong: <strong /> }}
                  />
                </p>
                <p className="text-xs text-muted-foreground">
                  {t('ForgotPasswordPage.success.spamHint')}
                </p>
                <Link to="/login">
                  <Button variant="outline" className="w-full">
                    <ArrowLeft className="mr-2 h-4 w-4" />
                    {t('ForgotPasswordPage.actions.backToLogin')}
                  </Button>
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
        {/* Logo */}
        <div className="flex flex-col items-center gap-2">
          <div className="flex items-center gap-2">
            <Network className="h-10 w-10 text-primary" />
            <span className="text-3xl font-bold gradient-text">FreeSDN</span>
          </div>
          <p className="text-muted-foreground text-sm">
            {t('ForgotPasswordPage.tagline')}
          </p>
        </div>
        
        <Card className="border-border/40 shadow-xl">
          <CardContent noOffset>
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-2 text-center">
                <h2 className="text-2xl font-semibold tracking-tight">{t('ForgotPasswordPage.title')}</h2>
                <p className="text-sm text-muted-foreground">
                  {t('ForgotPasswordPage.subtitle')}
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
                  <Label htmlFor="email">{t('ForgotPasswordPage.emailLabel')}</Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="admin@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    autoComplete="email"
                    autoFocus
                    required
                  />
                </div>
              </div>
              
              <Button type="submit" className="w-full" disabled={isLoading}>
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    {t('ForgotPasswordPage.actions.sending')}
                  </>
                ) : (
                  t('ForgotPasswordPage.actions.sendResetLink')
                )}
              </Button>
              
              <Link to="/login">
                <Button variant="ghost" className="w-full">
                  <ArrowLeft className="mr-2 h-4 w-4" />
                  {t('ForgotPasswordPage.actions.backToLogin')}
                </Button>
              </Link>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
