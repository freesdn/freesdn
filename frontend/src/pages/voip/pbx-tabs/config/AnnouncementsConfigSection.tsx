// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * AnnouncementsConfigSection · audio / announcement config cards (announcements,
 * paging groups, system recordings, music on hold) for the PBX Config tab.
 *
 * Pure render of `fullConfig` slices. Each Card is conditionally rendered
 * based on whether the corresponding array is non-empty.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useTranslation } from 'react-i18next';
import { Megaphone, Bell, Mic, Music } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export interface AnnouncementsConfigSectionProps {
  fullConfig: any;
}

export function AnnouncementsConfigSection({ fullConfig }: AnnouncementsConfigSectionProps) {
  const { t } = useTranslation('voip');
  return (
    <>
      {/* Announcements */}
      {(fullConfig.announcements?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <Megaphone className="h-4 w-4" /> {t('AnnouncementsConfigSection.announcements.title')} ({fullConfig.announcements.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2 pr-4">{t('AnnouncementsConfigSection.announcements.id')}</th><th className="pb-2 pr-4">{t('AnnouncementsConfigSection.announcements.description')}</th>
                  <th className="pb-2 pr-4">{t('AnnouncementsConfigSection.announcements.recording')}</th><th className="pb-2 pr-4">{t('AnnouncementsConfigSection.announcements.skip')}</th>
                  <th className="pb-2 pr-4">{t('AnnouncementsConfigSection.announcements.postDest')}</th>
                </tr></thead>
                <tbody>
                  {fullConfig.announcements.map((a: any, i: number) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-mono">{a.announcement_id}</td>
                      <td className="py-2 pr-4 font-medium">{a.description || '-'}</td>
                      <td className="py-2 pr-4 font-mono text-xs">{a.recording_id || '-'}</td>
                      <td className="py-2 pr-4">{a.allow_skip === '1' ? t('AnnouncementsConfigSection.common.yes') : t('AnnouncementsConfigSection.common.no')}</td>
                      <td className="py-2 pr-4 text-xs">{a.post_dest || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Paging Groups */}
      {(fullConfig.paging_groups?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <Bell className="h-4 w-4" /> {t('AnnouncementsConfigSection.pagingGroups.title')} ({fullConfig.paging_groups.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2 pr-4">{t('AnnouncementsConfigSection.pagingGroups.group')}</th><th className="pb-2 pr-4">{t('AnnouncementsConfigSection.pagingGroups.description')}</th><th className="pb-2 pr-4">{t('AnnouncementsConfigSection.pagingGroups.default')}</th>
                </tr></thead>
                <tbody>
                  {fullConfig.paging_groups.map((pg: any, i: number) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-mono">{pg.page_group}</td>
                      <td className="py-2 pr-4">{pg.description || '-'}</td>
                      <td className="py-2 pr-4">{(pg.is_default === '1' || pg.is_default === true) ? t('AnnouncementsConfigSection.common.yes') : t('AnnouncementsConfigSection.common.no')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* System Recordings */}
      {(fullConfig.system_recordings?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <Mic className="h-4 w-4" /> {t('AnnouncementsConfigSection.systemRecordings.title')} ({fullConfig.system_recordings.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2 pr-4">{t('AnnouncementsConfigSection.systemRecordings.name')}</th><th className="pb-2 pr-4">{t('AnnouncementsConfigSection.systemRecordings.filename')}</th>
                  <th className="pb-2 pr-4">{t('AnnouncementsConfigSection.systemRecordings.description')}</th><th className="pb-2 pr-4">{t('AnnouncementsConfigSection.systemRecordings.languages')}</th>
                </tr></thead>
                <tbody>
                  {fullConfig.system_recordings.map((r: any, i: number) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-medium">{r.displayname}</td>
                      <td className="py-2 pr-4 font-mono text-xs">{r.filename || '-'}</td>
                      <td className="py-2 pr-4 text-xs">{r.description || '-'}</td>
                      <td className="py-2 pr-4">{r.languages || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Music on Hold */}
      {(fullConfig.music_on_hold?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-base flex items-center gap-2">
              <Music className="h-4 w-4" /> {t('AnnouncementsConfigSection.musicOnHold.title')} ({fullConfig.music_on_hold.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2 pr-4">{t('AnnouncementsConfigSection.musicOnHold.category')}</th><th className="pb-2 pr-4">{t('AnnouncementsConfigSection.musicOnHold.type')}</th>
                  <th className="pb-2 pr-4">{t('AnnouncementsConfigSection.musicOnHold.random')}</th><th className="pb-2 pr-4">{t('AnnouncementsConfigSection.musicOnHold.format')}</th>
                </tr></thead>
                <tbody>
                  {fullConfig.music_on_hold.map((m: any, i: number) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-medium">{m.category}</td>
                      <td className="py-2 pr-4">{m.type || '-'}</td>
                      <td className="py-2 pr-4">{m.random ? t('AnnouncementsConfigSection.common.yes') : t('AnnouncementsConfigSection.common.no')}</td>
                      <td className="py-2 pr-4">{m.format || '-'}</td>
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
