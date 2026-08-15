// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * SecurityConfigSection · security / admin config cards (blacklist, certificates,
 * admin users, AMI managers) for the PBX Config tab.
 *
 * Pure render of `fullConfig` slices. Each Card is conditionally rendered
 * based on whether the corresponding array is non-empty.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useTranslation } from 'react-i18next';
import { Lock, FileKey, UserCog, Terminal, Check, Minus } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

export interface SecurityConfigSectionProps {
  fullConfig: any;
}

export function SecurityConfigSection({ fullConfig }: SecurityConfigSectionProps) {
  const { t } = useTranslation('voip');
  return (
    <>
      {/* Blacklist */}
      {(fullConfig.blacklist?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <Lock className="h-4 w-4" /> {t('SecurityConfigSection.blacklist.title', { count: fullConfig.blacklist.length })}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="flex flex-wrap gap-2">
              {fullConfig.blacklist.map((b: any, i: number) => (
                <Badge key={i} variant="destructive" className="font-mono">
                  {b.number || JSON.stringify(b)}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Certificates */}
      {(fullConfig.certificates?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <FileKey className="h-4 w-4" /> {t('SecurityConfigSection.certificates.title', { count: fullConfig.certificates.length })}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2 pr-4">{t('SecurityConfigSection.certificates.columns.name')}</th><th className="pb-2 pr-4">{t('SecurityConfigSection.certificates.columns.type')}</th>
                  <th className="pb-2 pr-4">{t('SecurityConfigSection.certificates.columns.description')}</th><th className="pb-2 pr-4">{t('SecurityConfigSection.certificates.columns.default')}</th>
                </tr></thead>
                <tbody>
                  {fullConfig.certificates.map((c: any, i: number) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-medium">{c.basename}</td>
                      <td className="py-2 pr-4">
                        <Badge variant="outline" className="text-[10px]">
                          {c.type === 'ss' ? t('SecurityConfigSection.certificates.types.selfSigned') : c.type === 'le' ? t('SecurityConfigSection.certificates.types.letsEncrypt') : c.type}
                        </Badge>
                      </td>
                      <td className="py-2 pr-4 text-xs">{c.description || '-'}</td>
                      <td className="py-2 pr-4">
                        {c.default === 'yes' || c.default === true ? (
                          <Check className="h-3.5 w-3.5 text-success" aria-label={t('SecurityConfigSection.certificates.columns.default')} />
                        ) : (
                          <Minus className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Admin Users */}
      {(fullConfig.admin_users?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <UserCog className="h-4 w-4" /> {t('SecurityConfigSection.adminUsers.title', { count: fullConfig.admin_users.length })}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2 pr-4">{t('SecurityConfigSection.adminUsers.columns.username')}</th><th className="pb-2 pr-4">{t('SecurityConfigSection.adminUsers.columns.extRange')}</th>
                  <th className="pb-2 pr-4">{t('SecurityConfigSection.adminUsers.columns.department')}</th>
                </tr></thead>
                <tbody>
                  {fullConfig.admin_users.map((u: any, i: number) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-medium">{u.username}</td>
                      <td className="py-2 pr-4 font-mono text-xs">
                        {u.extension_low && u.extension_high ? `${u.extension_low}-${u.extension_high}` : '-'}
                      </td>
                      <td className="py-2 pr-4">{u.deptname || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* AMI Managers */}
      {(fullConfig.ami_managers?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <Terminal className="h-4 w-4" /> {t('SecurityConfigSection.amiManagers.title', { count: fullConfig.ami_managers.length })}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2 pr-4">{t('SecurityConfigSection.amiManagers.columns.name')}</th><th className="pb-2 pr-4">{t('SecurityConfigSection.amiManagers.columns.permit')}</th>
                  <th className="pb-2 pr-4">{t('SecurityConfigSection.amiManagers.columns.read')}</th><th className="pb-2 pr-4">{t('SecurityConfigSection.amiManagers.columns.write')}</th>
                </tr></thead>
                <tbody>
                  {fullConfig.ami_managers.map((m: any, i: number) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-medium">{m.name}</td>
                      <td className="py-2 pr-4 font-mono text-xs">{m.permit || '-'}</td>
                      <td className="py-2 pr-4 text-xs">{Array.isArray(m.read) ? m.read.join(', ') : (m.read || '-')}</td>
                      <td className="py-2 pr-4 text-xs">{Array.isArray(m.write) ? m.write.join(', ') : (m.write || '-')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </>
  );
}
