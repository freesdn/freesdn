// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Setup Wizard: Organization Step
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { type OrganizationCreateRequest } from '@/lib/setup-api';
import { getApiErrorMessage } from '@/lib/api';
import { useSetupStore } from '@/stores/setupStore';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import {
  Loader2,
  Building2,
  ChevronRight,
  ChevronLeft,
} from 'lucide-react';

interface OrganizationStepProps {
  onNext: () => void;
  onPrevious: () => void;
}

const TIMEZONES = [
  'UTC',
  // Americas
  'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
  'America/Anchorage', 'America/Phoenix', 'America/Toronto', 'America/Vancouver',
  'America/Mexico_City', 'America/Bogota', 'America/Lima', 'America/Santiago',
  'America/Sao_Paulo', 'America/Buenos_Aires', 'Pacific/Honolulu',
  // Europe
  'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Madrid',
  'Europe/Rome', 'Europe/Amsterdam', 'Europe/Zurich', 'Europe/Stockholm',
  'Europe/Warsaw', 'Europe/Bucharest', 'Europe/Athens', 'Europe/Moscow',
  'Europe/Istanbul',
  // Middle East
  'Asia/Dubai', 'Asia/Riyadh', 'Asia/Tehran', 'Asia/Jerusalem',
  // Asia
  'Asia/Kolkata', 'Asia/Karachi', 'Asia/Dhaka', 'Asia/Bangkok',
  'Asia/Jakarta', 'Asia/Singapore', 'Asia/Hong_Kong', 'Asia/Shanghai',
  'Asia/Taipei', 'Asia/Seoul', 'Asia/Tokyo', 'Asia/Manila',
  // Oceania
  'Australia/Perth', 'Australia/Adelaide', 'Australia/Sydney',
  'Australia/Brisbane', 'Pacific/Auckland', 'Pacific/Fiji',
  // Africa
  'Africa/Cairo', 'Africa/Lagos', 'Africa/Johannesburg',
  'Africa/Nairobi', 'Africa/Casablanca',
];

const LOCALES = [
  { value: 'en-US', labelKey: 'locales.enUS' },
  { value: 'en-GB', labelKey: 'locales.enGB' },
  { value: 'es-ES', labelKey: 'locales.esES' },
  { value: 'fr-FR', labelKey: 'locales.frFR' },
  { value: 'de-DE', labelKey: 'locales.deDE' },
  { value: 'ja-JP', labelKey: 'locales.jaJP' },
  { value: 'zh-CN', labelKey: 'locales.zhCN' },
];

const TIME_FORMATS = [
  { value: '24h', labelKey: 'timeFormats.h24' },
  { value: '12h', labelKey: 'timeFormats.h12' },
];

const DATE_FORMATS = [
  { value: 'YYYY-MM-DD', labelKey: 'dateFormats.iso' },
  { value: 'MM/DD/YYYY', labelKey: 'dateFormats.us' },
  { value: 'DD/MM/YYYY', labelKey: 'dateFormats.eu' },
  { value: 'DD.MM.YYYY', labelKey: 'dateFormats.de' },
];

export function OrganizationStep({ onNext, onPrevious }: OrganizationStepProps) {
  const { t } = useTranslation('setup');
  // v2.6+: adminId is no longer threaded through here, Admin step
  // creates user + org atomically (see SetupPage.tsx note).
  const { setOrganizationInfo } = useSetupStore();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [formData, setFormData] = useState<OrganizationCreateRequest>({
    name: '',
    slug: '',
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
    locale: navigator.language || 'en-US',
    time_format: '24h',
    date_format: 'YYYY-MM-DD',
  });

  const generateSlug = (name: string): string => {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '')
      .replace(/[\s_]+/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '')
      .substring(0, 50);
  };

  const handleNameChange = (value: string) => {
    setFormData(prev => ({
      ...prev,
      name: value,
      slug: generateSlug(value),
    }));
    setError(null);
  };

  const handleChange = (field: keyof OrganizationCreateRequest, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    setError(null);
  };

  const validateForm = (): boolean => {
    if (!formData.name || formData.name.length < 2) {
      setError(t('OrganizationStep.validation.nameMin'));
      return false;
    }
    if (!formData.slug || formData.slug.length < 2) {
      setError(t('OrganizationStep.validation.slugMin'));
      return false;
    }
    if (!/^[a-z0-9-]+$/.test(formData.slug)) {
      setError(t('OrganizationStep.validation.slugPattern'));
      return false;
    }
    return true;
  };

  const handleSubmit = (e?: React.FormEvent) => {
    e?.preventDefault();

    if (!validateForm()) return;

    // v2.6+: Organization is collected BEFORE Admin so the Admin
    // step can submit user + org atomically to the new
    // ``/setup/admin`` endpoint. This step is purely client-state,
    // no backend call until Admin step fires.
    setSubmitting(true);
    setError(null);
    try {
      setOrganizationInfo(
        formData.name,
        formData.slug || '',
        '', // organization_id assigned by backend in Admin step
        '', // site_id assigned by backend in Admin step
      );
      onNext();
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, t('OrganizationStep.errors.capture')));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex flex-col min-h-full">
      <div className="flex-1 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">{t('OrganizationStep.title')}</h1>
        <p className="text-muted-foreground mt-1">
          {t('OrganizationStep.subtitle')}
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Building2 className="h-5 w-5" />
            {t('OrganizationStep.card.title')}
          </CardTitle>
          <CardDescription>
            {t('OrganizationStep.card.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">{t('OrganizationStep.fields.name.label')}</Label>
              <Input
                id="name"
                placeholder={t('OrganizationStep.fields.name.placeholder')}
                value={formData.name}
                onChange={(e) => handleNameChange(e.target.value)}
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="slug">{t('OrganizationStep.fields.slug.label')}</Label>
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">freesdn.local/</span>
                <Input
                  id="slug"
                  placeholder={t('OrganizationStep.fields.slug.placeholder')}
                  value={formData.slug}
                  onChange={(e) => handleChange('slug', e.target.value)}
                  className="flex-1"
                  required
                />
              </div>
              <p className="text-xs text-muted-foreground">
                {t('OrganizationStep.fields.slug.helper')}
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="timezone">{t('OrganizationStep.fields.timezone.label')}</Label>
                <Select
                  value={formData.timezone}
                  onValueChange={(value) => handleChange('timezone', value)}
                >
                  <SelectTrigger id="timezone">
                    <SelectValue placeholder={t('OrganizationStep.fields.timezone.placeholder')} />
                  </SelectTrigger>
                  <SelectContent>
                    {TIMEZONES.map((tz) => (
                      <SelectItem key={tz} value={tz}>
                        {tz}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="locale">{t('OrganizationStep.fields.locale.label')}</Label>
                <Select
                  value={formData.locale}
                  onValueChange={(value) => handleChange('locale', value)}
                >
                  <SelectTrigger id="locale">
                    <SelectValue placeholder={t('OrganizationStep.fields.locale.placeholder')} />
                  </SelectTrigger>
                  <SelectContent>
                    {LOCALES.map((locale) => (
                      <SelectItem key={locale.value} value={locale.value}>
                        {t(`OrganizationStep.${locale.labelKey}`)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="time_format">{t('OrganizationStep.fields.timeFormat.label')}</Label>
                <Select
                  value={formData.time_format}
                  onValueChange={(value) => handleChange('time_format', value)}
                >
                  <SelectTrigger id="time_format">
                    <SelectValue placeholder={t('OrganizationStep.fields.timeFormat.placeholder')} />
                  </SelectTrigger>
                  <SelectContent>
                    {TIME_FORMATS.map((fmt) => (
                      <SelectItem key={fmt.value} value={fmt.value}>
                        {t(`OrganizationStep.${fmt.labelKey}`)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="date_format">{t('OrganizationStep.fields.dateFormat.label')}</Label>
                <Select
                  value={formData.date_format}
                  onValueChange={(value) => handleChange('date_format', value)}
                >
                  <SelectTrigger id="date_format">
                    <SelectValue placeholder={t('OrganizationStep.fields.dateFormat.placeholder')} />
                  </SelectTrigger>
                  <SelectContent>
                    {DATE_FORMATS.map((fmt) => (
                      <SelectItem key={fmt.value} value={fmt.value}>
                        {t(`OrganizationStep.${fmt.labelKey}`)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {error && (
              <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
                <p className="text-destructive text-sm">{error}</p>
              </div>
            )}
          </form>
        </CardContent>
      </Card>

      </div>

      <div className="sticky bottom-0 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80 border-t border-border/50 pt-4 pb-4 -mx-1 px-1 mt-6">
        <div className="flex justify-between">
          <Button variant="outline" onClick={onPrevious}>
            <ChevronLeft className="mr-2 h-4 w-4" />
            {t('OrganizationStep.actions.previous')}
          </Button>
          <Button
            onClick={() => handleSubmit()}
            disabled={submitting || !formData.name || formData.name.length < 2 || !formData.slug || formData.slug.length < 2}
          >
            {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {t('OrganizationStep.actions.continue')}
            <ChevronRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}
