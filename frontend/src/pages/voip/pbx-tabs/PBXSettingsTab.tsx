// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PBXSettingsTab · connection-settings + danger-zone tab for the PBX detail page.
 *
 * Extracted from PBXDetailPage as part of the monolith breakup. This tab owns
 * its own form state (`settingsForm`, `showPassword`, `settingsInitialized`)
 * since none of it is needed by the parent or sibling tabs. The parent only
 * supplies the source `pbx` data (used to seed the form once) and the three
 * mutations that act on it (save / test connection / delete).
 *
 * Behaviourally identical to the inline implementation: form initialises once
 * from `pbx.settings`, the password reveal toggle is local, and the Delete
 * button still goes through `confirm()`.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { UseMutationResult } from '@tanstack/react-query';
import {
  Save, Plug, Loader2, Trash2, Eye, EyeOff,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import type { PBXSystem } from '../types';

export interface PBXSettingsTabProps {
  pbx: PBXSystem | null;
  pbxName: string;
  updatePBXMutation: UseMutationResult<any, unknown, any, unknown>;
  connectMutation: UseMutationResult<any, unknown, void, unknown>;
  deletePBXMutation: UseMutationResult<any, unknown, void, unknown>;
}

export function PBXSettingsTab({
  pbx,
  pbxName,
  updatePBXMutation,
  connectMutation,
  deletePBXMutation,
}: PBXSettingsTabProps) {
  const { t } = useTranslation('voip');
  const [settingsInitialized, setSettingsInitialized] = useState(false);
  const [settingsForm, setSettingsForm] = useState({
    name: '', ip_address: '', api_port: 443, sip_port: 5060,
    description: '', api_username: '', api_password: '',
  });
  const [showPassword, setShowPassword] = useState(false);

  useEffect(() => {
    if (pbx && !settingsInitialized) {
      const s = (pbx.settings || {}) as Record<string, string>;
      setSettingsForm({
        name: pbx.name,
        ip_address: pbx.ip_address || '',
        api_port: pbx.api_port || 443,
        sip_port: pbx.sip_port || 5060,
        description: pbx.description || '',
        api_username: s.api_username || '',
        api_password: s.api_password || '',
      });
      setSettingsInitialized(true);
    }
  }, [pbx, settingsInitialized]);

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>{t('PBXSettingsTab.connection.title')}</CardTitle>
          <CardDescription>{t('PBXSettingsTab.connection.description')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-2">
              <Label>{t('PBXSettingsTab.fields.displayName')}</Label>
              <Input value={settingsForm.name}
                onChange={(e) => setSettingsForm({ ...settingsForm, name: e.target.value })} />
            </div>
            <div className="grid gap-2">
              <Label>{t('PBXSettingsTab.fields.description')}</Label>
              <Input value={settingsForm.description}
                onChange={(e) => setSettingsForm({ ...settingsForm, description: e.target.value })} />
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
            <div className="grid gap-2">
              <Label>{t('PBXSettingsTab.fields.ipAddress')}</Label>
              <Input value={settingsForm.ip_address}
                onChange={(e) => setSettingsForm({ ...settingsForm, ip_address: e.target.value })} />
            </div>
            <div className="grid gap-2">
              <Label>{t('PBXSettingsTab.fields.apiPort')}</Label>
              <Input type="number" value={settingsForm.api_port}
                onChange={(e) => setSettingsForm({ ...settingsForm, api_port: parseInt(e.target.value) || 443 })} />
            </div>
            <div className="grid gap-2">
              <Label>{t('PBXSettingsTab.fields.sipPort')}</Label>
              <Input type="number" value={settingsForm.sip_port}
                onChange={(e) => setSettingsForm({ ...settingsForm, sip_port: parseInt(e.target.value) || 5060 })} />
            </div>
          </div>
          <Separator />
          <h4 className="text-sm font-medium">{t('PBXSettingsTab.auth.heading')}</h4>
          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-2">
              <Label>{t('PBXSettingsTab.fields.username')}</Label>
              <Input value={settingsForm.api_username}
                onChange={(e) => setSettingsForm({ ...settingsForm, api_username: e.target.value })} />
            </div>
            <div className="grid gap-2">
              <Label>{t('PBXSettingsTab.fields.password')}</Label>
              <div className="relative">
                <Input
                  type={showPassword ? 'text' : 'password'}
                  value={settingsForm.api_password}
                  onChange={(e) => setSettingsForm({ ...settingsForm, api_password: e.target.value })}
                />
                <button
                  type="button"
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3 pt-2">
            <Button
              onClick={() => updatePBXMutation.mutate({
                name: settingsForm.name,
                ip_address: settingsForm.ip_address,
                api_port: settingsForm.api_port,
                sip_port: settingsForm.sip_port,
                description: settingsForm.description || undefined,
                api_username: settingsForm.api_username || undefined,
                api_password: settingsForm.api_password || undefined,
              })}
              disabled={updatePBXMutation.isPending}
            >
              {updatePBXMutation.isPending
                ? <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                : <Save className="h-4 w-4 mr-2" />}
              {t('PBXSettingsTab.actions.saveSettings')}
            </Button>
            <Button variant="outline"
              onClick={() => connectMutation.mutate()}
              disabled={connectMutation.isPending}
            >
              {connectMutation.isPending
                ? <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                : <Plug className="h-4 w-4 mr-2" />}
              {t('PBXSettingsTab.actions.testConnection')}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card className="border-red-500/20">
        <CardHeader>
          <CardTitle className="text-red-600">{t('PBXSettingsTab.dangerZone.title')}</CardTitle>
          <CardDescription>{t('PBXSettingsTab.dangerZone.description')}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button variant="destructive" size="sm"
            onClick={() => {
              if (confirm(t('PBXSettingsTab.dangerZone.deleteConfirm', { name: pbxName }))) {
                deletePBXMutation.mutate();
              }
            }}
          >
            <Trash2 className="h-4 w-4 mr-2" /> {t('PBXSettingsTab.actions.deletePBX')}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
