// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * ProfilesTab · port profile cards for the switch detail view.
 *
 * Extracted from SwitchesPage as part of the monolith breakup. Receives all
 * data via props; emits open-create / edit / duplicate / delete callbacks to
 * the parent (which owns the dialog + mutations).
 */
import {
  Camera,
  Copy,
  MoreVertical,
  Pencil,
  Phone,
  Plug,
  Plus,
  Printer,
  RefreshCw,
  Settings2,
  Trash2,
  Wifi,
  type LucideIcon,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { EmptyState } from '@/components/ui/empty-state';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import type { SwitchPortProfile } from '@/lib/api';

const getProfileIcon = (type: string): LucideIcon => {
  switch (type) {
    case 'ap':
      return Wifi;
    case 'camera':
      return Camera;
    case 'voip':
      return Phone;
    case 'printer':
      return Printer;
    case 'iot':
      return Plug;
    default:
      return Settings2;
  }
};

export interface ProfilesTabProps {
  profiles: SwitchPortProfile[] | undefined;
  profilesLoading: boolean;
  onCreate: () => void;
  onEdit: (profile: SwitchPortProfile) => void;
  onDuplicate: (profile: SwitchPortProfile) => void;
  onDelete: (profile: SwitchPortProfile) => void;
}

export function ProfilesTab({
  profiles,
  profilesLoading,
  onCreate,
  onEdit,
  onDuplicate,
  onDelete,
}: ProfilesTabProps) {
  const { t } = useTranslation('switches');
  return (
    <>
      <div className="flex justify-end">
        <Button onClick={onCreate} size="sm">
          <Plus className="mr-2 h-4 w-4" aria-hidden="true" />
          {t('ProfilesTab.actions.createProfile')}
        </Button>
      </div>

      {profilesLoading && (
        <div className="flex items-center justify-center py-8">
          <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      )}

      {!profilesLoading && (!profiles || profiles.length === 0) && (
        <Card>
          <EmptyState
            icon={Copy}
            title={t('ProfilesTab.empty.title')}
            description={t('ProfilesTab.empty.description')}
          />
        </Card>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        {profiles?.map((profile) => {
          const ProfileIcon = getProfileIcon(profile.profile_type);
          return (
          <Card key={profile.id}>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <ProfileIcon className="h-5 w-5" aria-hidden="true" />
                  </div>
                  <div>
                    <CardTitle className="text-lg">{profile.name}</CardTitle>
                    <CardDescription>{profile.description}</CardDescription>
                  </div>
                </div>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="icon" aria-label={profile.name}>
                      <MoreVertical className="h-4 w-4" aria-hidden="true" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={() => onEdit(profile)}>
                      <Pencil className="mr-2 h-4 w-4" aria-hidden="true" />
                      {t('ProfilesTab.actions.edit')}
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => onDuplicate(profile)}>
                      <Copy className="mr-2 h-4 w-4" aria-hidden="true" />
                      {t('ProfilesTab.actions.duplicate')}
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      className="text-destructive focus:text-destructive"
                      onClick={() => onDelete(profile)}
                    >
                      <Trash2 className="mr-2 h-4 w-4" aria-hidden="true" />
                      {t('ProfilesTab.actions.delete')}
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">{t('ProfilesTab.fields.profileType')}</span>
                  <span className="capitalize">{profile.profile_type}</span>
                </div>
                {profile.native_vlan != null && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">{t('SwitchesPage.portDialog.nativeVlan')}</span>
                    <span>{profile.native_vlan}</span>
                  </div>
                )}
                {profile.tagged_vlans && profile.tagged_vlans.length > 0 && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">{t('SwitchesPage.portDialog.taggedVlans')}</span>
                    <span>{profile.tagged_vlans.join(', ')}</span>
                  </div>
                )}
                {profile.voice_vlan != null && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">{t('SwitchesPage.portDialog.voiceVlan')}</span>
                    <span>{profile.voice_vlan}</span>
                  </div>
                )}
                <div className="flex justify-between pt-2 border-t">
                  <span className="text-muted-foreground">{t('ProfilesTab.fields.portsUsing')}</span>
                  <Badge variant="secondary">{profile.ports_using}</Badge>
                </div>
              </div>
            </CardContent>
          </Card>
          );
        })}
      </div>
    </>
  );
}
