// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * SystemConfigSection · system / misc config cards (contacts, backup jobs,
 * SIP settings, parking, feature codes, installed modules) for the PBX Config tab.
 *
 * Pure render of `fullConfig` slices. Each Card is conditionally rendered
 * based on whether the corresponding array is non-empty.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useTranslation } from 'react-i18next';
import { Contact, HardDrive, Globe, ParkingSquare, Star, Package } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

export interface SystemConfigSectionProps {
  fullConfig: any;
}

export function SystemConfigSection({ fullConfig }: SystemConfigSectionProps) {
  const { t } = useTranslation('voip');
  return (
    <>
      {/* Contacts */}
      {(fullConfig.contacts?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <Contact className="h-4 w-4" /> {t('SystemConfigSection.cards.contacts.title')} ({fullConfig.contacts.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2 pr-4">{t('SystemConfigSection.contacts.columns.name')}</th><th className="pb-2 pr-4">{t('SystemConfigSection.contacts.columns.extension')}</th>
                  <th className="pb-2 pr-4">{t('SystemConfigSection.contacts.columns.email')}</th><th className="pb-2 pr-4">{t('SystemConfigSection.contacts.columns.company')}</th>
                  <th className="pb-2 pr-4">{t('SystemConfigSection.contacts.columns.department')}</th>
                </tr></thead>
                <tbody>
                  {fullConfig.contacts.map((c: any, i: number) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-medium">{c.displayname || `${c.fname || ''} ${c.lname || ''}`.trim() || '-'}</td>
                      <td className="py-2 pr-4 font-mono text-xs">{c.default_extension || '-'}</td>
                      <td className="py-2 pr-4 text-xs">{c.email || '-'}</td>
                      <td className="py-2 pr-4">{c.company || '-'}</td>
                      <td className="py-2 pr-4">{c.department || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Backup Jobs */}
      {(fullConfig.backup_jobs?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <HardDrive className="h-4 w-4" /> {t('SystemConfigSection.cards.backupJobs.title')} ({fullConfig.backup_jobs.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2 pr-4">{t('SystemConfigSection.backupJobs.columns.name')}</th><th className="pb-2 pr-4">{t('SystemConfigSection.backupJobs.columns.description')}</th>
                </tr></thead>
                <tbody>
                  {fullConfig.backup_jobs.map((b: any, i: number) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-medium">{b.name}</td>
                      <td className="py-2 pr-4 text-xs">{b.description || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* SIP Settings */}
      {fullConfig.sip_settings && Object.keys(fullConfig.sip_settings).length > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <Globe className="h-4 w-4" /> {t('SystemConfigSection.cards.sipSettings.title', { count: Object.keys(fullConfig.sip_settings).length })}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
              {Object.entries(fullConfig.sip_settings).map(([key, val]: [string, any]) => (
                <div key={key} className="flex justify-between items-center py-1 px-2 rounded bg-muted/30 text-sm">
                  <span className="text-muted-foreground truncate mr-2">{key}</span>
                  <span className="font-mono text-xs font-medium truncate max-w-[200px]">{String(val)}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Parking */}
      {fullConfig.parking && Object.keys(fullConfig.parking).length > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <ParkingSquare className="h-4 w-4" /> {t('SystemConfigSection.cards.parking.title')}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
              {Object.entries(fullConfig.parking).map(([key, val]: [string, any]) => (
                <div key={key} className="bg-muted/30 rounded p-2">
                  <p className="text-xs text-muted-foreground">{key}</p>
                  <p className="text-sm font-medium font-mono">{String(val)}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Feature Codes */}
      {(fullConfig.feature_codes?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <Star className="h-4 w-4" /> {t('SystemConfigSection.cards.featureCodes.title')} ({fullConfig.feature_codes.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="flex flex-wrap gap-2">
              {fullConfig.feature_codes.map((code: string, i: number) => (
                <Badge key={i} variant="secondary" className="font-mono text-xs">
                  {code}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Installed Modules */}
      {(fullConfig.installed_modules?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <Package className="h-4 w-4" /> {t('SystemConfigSection.cards.installedModules.title')} ({fullConfig.installed_modules.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="flex flex-wrap gap-1.5">
              {fullConfig.installed_modules.map((mod: string, i: number) => (
                <Badge key={i} variant="outline" className="text-xs">
                  {mod}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </>
  );
}
