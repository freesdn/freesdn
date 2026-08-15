// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, Link } from 'react-router-dom';
import { useAuthStore } from '../../stores/authStore';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Card, CardContent } from '../ui/card';
import { Network, Eye, EyeOff, Loader2, AlertCircle, Check } from 'lucide-react';

export function RegisterPage() {
  const { t } = useTranslation('common');
  const navigate = useNavigate();
  const { register, isLoading, error, clearError } = useAuthStore();

  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    first_name: '',
    last_name: '',
    organization_name: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [success, setSuccess] = useState(false);
  const [passwordErrors, setPasswordErrors] = useState<string[]>([]);
  
  const validatePassword = (password: string): string[] => {
    const errors: string[] = [];
    if (password.length < 12) errors.push(t('RegisterPage.passwordRules.minLength'));
    if (!/[a-z]/.test(password)) errors.push(t('RegisterPage.passwordRules.lowercase'));
    if (!/[A-Z]/.test(password)) errors.push(t('RegisterPage.passwordRules.uppercase'));
    if (!/[0-9]/.test(password)) errors.push(t('RegisterPage.passwordRules.number'));
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) errors.push(t('RegisterPage.passwordRules.special'));
    return errors;
  };
  
  const handlePasswordChange = (password: string) => {
    setFormData({ ...formData, password });
    setPasswordErrors(validatePassword(password));
  };
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();
    
    // Validate passwords match
    if (formData.password !== formData.confirmPassword) {
      return;
    }
    
    // Validate password requirements
    const errors = validatePassword(formData.password);
    if (errors.length > 0) {
      setPasswordErrors(errors);
      return;
    }
    
    const result = await register({
      email: formData.email,
      password: formData.password,
      first_name: formData.first_name,
      last_name: formData.last_name,
      organization_name: formData.organization_name || undefined,
    });
    
    if (result) {
      setSuccess(true);
    }
  };
  
  // Success state
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
                <h2 className="text-xl font-semibold">{t('RegisterPage.success.title')}</h2>
                <p className="text-sm text-muted-foreground">
                  {t('RegisterPage.success.description')}
                </p>
                <Button onClick={() => navigate('/login')} className="w-full">
                  {t('RegisterPage.success.goToLogin')}
                </Button>
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
            {t('RegisterPage.tagline')}
          </p>
        </div>
        
        <Card className="border-border/40 shadow-xl">
          <CardContent noOffset>
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-2 text-center">
                <h2 className="text-2xl font-semibold tracking-tight">{t('RegisterPage.heading')}</h2>
                <p className="text-sm text-muted-foreground">
                  {t('RegisterPage.subheading')}
                </p>
              </div>
              
              {error && (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-destructive/10 text-destructive text-sm">
                  <AlertCircle className="h-4 w-4 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}
              
              <div className="space-y-4">
                {/* Name fields */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="first_name">{t('RegisterPage.fields.firstName')}</Label>
                    <Input
                      id="first_name"
                      type="text"
                      placeholder={t('RegisterPage.placeholders.firstName')}
                      value={formData.first_name}
                      onChange={(e) => setFormData({ ...formData, first_name: e.target.value })}
                      autoComplete="given-name"
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="last_name">{t('RegisterPage.fields.lastName')}</Label>
                    <Input
                      id="last_name"
                      type="text"
                      placeholder={t('RegisterPage.placeholders.lastName')}
                      value={formData.last_name}
                      onChange={(e) => setFormData({ ...formData, last_name: e.target.value })}
                      autoComplete="family-name"
                      required
                    />
                  </div>
                </div>
                
                {/* Email */}
                <div className="space-y-2">
                  <Label htmlFor="email">{t('RegisterPage.fields.email')}</Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="john.doe@example.com"
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    autoComplete="email"
                    required
                  />
                </div>
                
                {/* Organization */}
                <div className="space-y-2">
                  <Label htmlFor="organization_name">
                    {t('RegisterPage.fields.organizationName')} <span className="text-muted-foreground">{t('RegisterPage.fields.optional')}</span>
                  </Label>
                  <Input
                    id="organization_name"
                    type="text"
                    placeholder={t('RegisterPage.placeholders.organizationName')}
                    value={formData.organization_name}
                    onChange={(e) => setFormData({ ...formData, organization_name: e.target.value })}
                  />
                </div>
                
                {/* Password */}
                <div className="space-y-2">
                  <Label htmlFor="password">{t('RegisterPage.fields.password')}</Label>
                  <div className="relative">
                    <Input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      placeholder="••••••••••••"
                      value={formData.password}
                      onChange={(e) => handlePasswordChange(e.target.value)}
                      autoComplete="new-password"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                    >
                      {showPassword ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                  
                  {/* Password requirements */}
                  {formData.password && (
                    <div className="text-xs space-y-1 mt-2">
                      {[
                        { text: t('RegisterPage.passwordRules.minLength'), valid: formData.password.length >= 12 },
                        { text: t('RegisterPage.passwordRules.lowercase'), valid: /[a-z]/.test(formData.password) },
                        { text: t('RegisterPage.passwordRules.uppercase'), valid: /[A-Z]/.test(formData.password) },
                        { text: t('RegisterPage.passwordRules.number'), valid: /[0-9]/.test(formData.password) },
                        { text: t('RegisterPage.passwordRules.special'), valid: /[!@#$%^&*(),.?":{}|<>]/.test(formData.password) },
                      ].map((req, i) => (
                        <div
                          key={i}
                          className={`flex items-center gap-1 ${
                            req.valid ? 'text-green-500' : 'text-muted-foreground'
                          }`}
                        >
                          <Check className={`h-3 w-3 ${req.valid ? 'opacity-100' : 'opacity-30'}`} />
                          <span>{req.text}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                
                {/* Confirm Password */}
                <div className="space-y-2">
                  <Label htmlFor="confirmPassword">{t('RegisterPage.fields.confirmPassword')}</Label>
                  <Input
                    id="confirmPassword"
                    type={showPassword ? 'text' : 'password'}
                    placeholder="••••••••••••"
                    value={formData.confirmPassword}
                    onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                    autoComplete="new-password"
                    required
                  />
                  {formData.confirmPassword && formData.password !== formData.confirmPassword && (
                    <p className="text-xs text-destructive">{t('RegisterPage.passwordMismatch')}</p>
                  )}
                </div>
              </div>
              
              <Button
                type="submit"
                className="w-full"
                disabled={
                  isLoading ||
                  passwordErrors.length > 0 ||
                  formData.password !== formData.confirmPassword
                }
              >
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    {t('RegisterPage.submitting')}
                  </>
                ) : (
                  t('RegisterPage.submit')
                )}
              </Button>
              
              <div className="text-center text-sm">
                <span className="text-muted-foreground">{t('RegisterPage.haveAccount')} </span>
                <Link to="/login" className="text-primary hover:underline font-medium">
                  {t('RegisterPage.signIn')}
                </Link>
              </div>
            </form>
          </CardContent>
        </Card>
        
        <p className="text-center text-xs text-muted-foreground">
          {t('RegisterPage.legal.prefix')}{' '}
          <a href="#" className="hover:text-primary transition-colors">{t('RegisterPage.legal.terms')}</a>
          {' '}{t('RegisterPage.legal.and')}{' '}
          <a href="#" className="hover:text-primary transition-colors">{t('RegisterPage.legal.privacy')}</a>
        </p>
      </div>
    </div>
  );
}
