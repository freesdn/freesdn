// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * CameraAccessPanel · Per-camera RBAC management
 *
 * Enterprise camera permission management:
 *  - View/grant/revoke per-camera access to specific users
 *  - Three access levels: viewer, operator, full
 *  - Granular capability flags (live, playback, PTZ, export, configure)
 *  - Time-limited access grants (contractor scenarios)
 *  - Group-based grants (assign access via camera groups)
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { cameraAccessApi } from '@/lib/api';
import type { CameraAccessGrant } from '@/lib/api/cameras';
import { usersApi } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import {
  Shield,
  UserPlus,
  Trash2,
  Eye,
  Video,
  Move,
  Download,
  Settings,
  Clock,
  AlertTriangle,
  Loader2,
  X,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface CameraAccessPanelProps {
  cameraId: string;
  cameraName?: string;
}

const ACCESS_LEVELS = {
  viewer: { labelKey: 'levels.viewer.label', color: 'bg-blue-500/10 text-blue-500', descKey: 'levels.viewer.desc' },
  operator: { labelKey: 'levels.operator.label', color: 'bg-amber-500/10 text-amber-500', descKey: 'levels.operator.desc' },
  full: { labelKey: 'levels.full.label', color: 'bg-emerald-500/10 text-emerald-500', descKey: 'levels.full.desc' },
} as const;

export function CameraAccessPanel({ cameraId, cameraName }: CameraAccessPanelProps) {
  const { t } = useTranslation('common');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showAddForm, setShowAddForm] = useState(false);

  // Fetch grants for this camera
  const { data: grantsData, isLoading, isError, refetch } = useQuery({
    queryKey: ['camera-access-grants', cameraId],
    queryFn: async () => (await cameraAccessApi.listGrants({ camera_id: cameraId })).data,
  });

  const grants = grantsData?.items ?? [];

  // Delete mutation
  const deleteMut = useMutation({
    mutationFn: (grantId: string) => cameraAccessApi.deleteGrant(grantId),
    onSuccess: () => {
      toast({ title: t('CameraAccessPanel.toasts.revoked') });
      queryClient.invalidateQueries({ queryKey: ['camera-access-grants', cameraId] });
    },
    onError: () => toast({ title: t('CameraAccessPanel.toasts.revokeFailed'), variant: 'destructive' as any }),
  });

  // Update mutation
  const updateMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof cameraAccessApi.updateGrant>[1] }) =>
      cameraAccessApi.updateGrant(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['camera-access-grants', cameraId] });
    },
    onError: () => toast({ title: t('CameraAccessPanel.toasts.updateFailed'), variant: 'destructive' as any }),
  });

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <Shield className="h-4 w-4" />
            {t('CameraAccessPanel.title')}
          </h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            {t('CameraAccessPanel.description', { camera: cameraName || t('CameraAccessPanel.thisCamera') })}
          </p>
        </div>
        <Button size="sm" className="gap-1.5" onClick={() => setShowAddForm(!showAddForm)}>
          {showAddForm ? <X className="h-4 w-4" /> : <UserPlus className="h-4 w-4" />}
          {showAddForm ? t('CameraAccessPanel.actions.cancel') : t('CameraAccessPanel.actions.grantAccess')}
        </Button>
      </div>

      {/* Add Grant Form */}
      {showAddForm && (
        <AddGrantForm
          cameraId={cameraId}
          onSuccess={() => {
            setShowAddForm(false);
            refetch();
          }}
        />
      )}

      {/* Loading / Error */}
      {isLoading && (
        <div className="flex items-center justify-center gap-2 p-6 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span className="text-sm">{t('CameraAccessPanel.loading')}</span>
        </div>
      )}
      {isError && (
        <div className="flex items-center gap-2 p-3 text-sm text-red-500 bg-red-500/10 rounded-md">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          {t('CameraAccessPanel.loadError')}
          <Button size="sm" variant="outline" className="ml-2 h-7 text-xs" onClick={() => refetch()}>{t('CameraAccessPanel.actions.retry')}</Button>
        </div>
      )}

      {/* Grants List */}
      {!isLoading && !isError && grants.length === 0 && (
        <Card>
          <CardContent noOffset className="p-6 text-center text-muted-foreground">
            <Shield className="h-8 w-8 mx-auto mb-2 opacity-40" />
            <p className="text-sm font-medium">{t('CameraAccessPanel.empty.title')}</p>
            <p className="text-xs mt-1">
              {t('CameraAccessPanel.empty.descBefore')} <Badge variant="secondary" className="text-[10px]">cameras.view</Badge> {t('CameraAccessPanel.empty.descAfter')}
            </p>
          </CardContent>
        </Card>
      )}

      {grants.length > 0 && (
        <Card>
          <div className="divide-y">
            {grants.map((grant) => (
              <GrantRow
                key={grant.id}
                grant={grant}
                onUpdate={(data) => updateMut.mutate({ id: grant.id, data })}
                onDelete={() => {
                  if (confirm(t('CameraAccessPanel.confirmRevoke', { user: grant.user_email || grant.user_id }))) {
                    deleteMut.mutate(grant.id);
                  }
                }}
                isPending={updateMut.isPending || deleteMut.isPending}
              />
            ))}
          </div>
        </Card>
      )}

      {/* Info banner */}
      <div className="text-xs text-muted-foreground bg-muted/30 rounded-lg p-3 space-y-1">
        <p className="font-medium">{t('CameraAccessPanel.info.heading')}</p>
        <ul className="list-disc list-inside space-y-0.5 ml-1">
          <li>{t('CameraAccessPanel.info.orgAdmins')}</li>
          <li>{t('CameraAccessPanel.info.siteAdmins')}</li>
          <li>{t('CameraAccessPanel.info.explicitGrants')}</li>
          <li>{t('CameraAccessPanel.info.groupGrants')}</li>
          <li>{t('CameraAccessPanel.info.timeLimited')}</li>
        </ul>
      </div>
    </div>
  );
}

// ── Grant Row Component ──────────────────────────────────────────────────────

function GrantRow({
  grant,
  onUpdate,
  onDelete,
  isPending,
}: {
  grant: CameraAccessGrant;
  onUpdate: (data: Parameters<typeof cameraAccessApi.updateGrant>[1]) => void;
  onDelete: () => void;
  isPending: boolean;
}) {
  const { t } = useTranslation('common');
  const level = ACCESS_LEVELS[grant.access_level as keyof typeof ACCESS_LEVELS] || ACCESS_LEVELS.viewer;
  const isExpired = grant.expires_at && new Date(grant.expires_at) < new Date();

  return (
    <div className={cn('flex items-center gap-3 px-4 py-3', isExpired && 'opacity-50')}>
      {/* User info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium truncate">{grant.user_name || grant.user_email || t('CameraAccessPanel.unknownUser')}</span>
          {grant.user_email && grant.user_name && (
            <span className="text-xs text-muted-foreground truncate">{grant.user_email}</span>
          )}
        </div>
        <div className="flex items-center gap-2 mt-1">
          <Badge variant="secondary" className={cn('text-[10px]', level.color)}>
            {t(`CameraAccessPanel.${level.labelKey}`)}
          </Badge>
          {/* Capability icons */}
          <div className="flex items-center gap-1.5 text-muted-foreground">
            {grant.can_live && <span title={t('CameraAccessPanel.capabilities.live')}><Eye className="h-3 w-3" /></span>}
            {grant.can_playback && <span title={t('CameraAccessPanel.capabilities.playback')}><Video className="h-3 w-3" /></span>}
            {grant.can_ptz && <span title={t('CameraAccessPanel.capabilities.ptz')}><Move className="h-3 w-3" /></span>}
            {grant.can_export && <span title={t('CameraAccessPanel.capabilities.export')}><Download className="h-3 w-3" /></span>}
            {grant.can_configure && <span title={t('CameraAccessPanel.capabilities.configure')}><Settings className="h-3 w-3" /></span>}
          </div>
          {isExpired && (
            <Badge variant="destructive" className="text-[10px]">{t('CameraAccessPanel.expired')}</Badge>
          )}
          {grant.expires_at && !isExpired && (
            <span className="text-[10px] text-muted-foreground flex items-center gap-0.5">
              <Clock className="h-3 w-3" />
              {t('CameraAccessPanel.expiresOn', { date: new Date(grant.expires_at).toLocaleDateString() })}
            </span>
          )}
        </div>
      </div>

      {/* Access level selector */}
      <Select
        value={grant.access_level}
        onValueChange={(v) => {
          const presets = {
            viewer: { can_live: true, can_playback: false, can_ptz: false, can_export: false, can_configure: false },
            operator: { can_live: true, can_playback: true, can_ptz: true, can_export: false, can_configure: false },
            full: { can_live: true, can_playback: true, can_ptz: true, can_export: true, can_configure: true },
          };
          onUpdate({ access_level: v, ...presets[v as keyof typeof presets] });
        }}
      >
        <SelectTrigger className="w-[110px] h-8 text-xs">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="viewer">{t('CameraAccessPanel.levels.viewer.label')}</SelectItem>
          <SelectItem value="operator">{t('CameraAccessPanel.levels.operator.label')}</SelectItem>
          <SelectItem value="full">{t('CameraAccessPanel.levels.full.label')}</SelectItem>
        </SelectContent>
      </Select>

      {/* Delete */}
      <Button
        size="icon"
        variant="ghost"
        className="h-8 w-8 text-muted-foreground hover:text-red-500"
        onClick={onDelete}
        disabled={isPending}
        title={t('CameraAccessPanel.actions.revokeAccess')}
      >
        <Trash2 className="h-4 w-4" />
      </Button>
    </div>
  );
}

// ── Add Grant Form ───────────────────────────────────────────────────────────

function AddGrantForm({
  cameraId,
  onSuccess,
}: {
  cameraId: string;
  onSuccess: () => void;
}) {
  const { t } = useTranslation('common');
  const { toast } = useToast();
  const [userId, setUserId] = useState('');
  const [accessLevel, setAccessLevel] = useState('viewer');
  const [expiresIn, setExpiresIn] = useState('');
  const queryClient = useQueryClient();

  // Fetch org users for the dropdown
  const { data: usersData } = useQuery({
    queryKey: ['org-users'],
    queryFn: async () => (await usersApi.list()).data,
    staleTime: 60_000,
  });
  const rawUsers = (usersData as any)?.items ?? usersData ?? [];
  const users = Array.isArray(rawUsers) ? rawUsers : [];

  const createMut = useMutation({
    mutationFn: () => {
      const presets = {
        viewer: { can_live: true, can_playback: false, can_ptz: false, can_export: false, can_configure: false },
        operator: { can_live: true, can_playback: true, can_ptz: true, can_export: false, can_configure: false },
        full: { can_live: true, can_playback: true, can_ptz: true, can_export: true, can_configure: true },
      };
      const data: Parameters<typeof cameraAccessApi.createGrant>[0] = {
        user_id: userId,
        camera_id: cameraId,
        access_level: accessLevel,
        ...presets[accessLevel as keyof typeof presets],
      };
      if (expiresIn) {
        const days = parseInt(expiresIn, 10);
        if (!isNaN(days) && days >= 1) {
          const d = new Date();
          d.setDate(d.getDate() + days);
          data.expires_at = d.toISOString();
        }
      }
      return cameraAccessApi.createGrant(data);
    },
    onSuccess: () => {
      toast({ title: t('CameraAccessPanel.toasts.granted') });
      queryClient.invalidateQueries({ queryKey: ['camera-access-grants', cameraId] });
      onSuccess();
    },
    onError: () => toast({ title: t('CameraAccessPanel.toasts.grantFailed'), variant: 'destructive' as any }),
  });

  return (
    <Card>
      <CardContent noOffset className="p-4 space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {/* User select */}
          <div>
            <Label className="text-xs">{t('CameraAccessPanel.form.userLabel')}</Label>
            <Select value={userId} onValueChange={setUserId}>
              <SelectTrigger className="h-9 text-xs mt-1">
                <SelectValue placeholder={t('CameraAccessPanel.form.userPlaceholder')} />
              </SelectTrigger>
              <SelectContent>
                {(users as any[]).map((u: any) => (
                  <SelectItem key={u.id} value={u.id}>
                    {u.full_name || u.email || u.username}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Access level */}
          <div>
            <Label className="text-xs">{t('CameraAccessPanel.form.accessLevelLabel')}</Label>
            <Select value={accessLevel} onValueChange={setAccessLevel}>
              <SelectTrigger className="h-9 text-xs mt-1">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="viewer">{t('CameraAccessPanel.form.options.viewer')}</SelectItem>
                <SelectItem value="operator">{t('CameraAccessPanel.form.options.operator')}</SelectItem>
                <SelectItem value="full">{t('CameraAccessPanel.form.options.full')}</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Expiry */}
          <div>
            <Label className="text-xs">{t('CameraAccessPanel.form.expiresLabel')}</Label>
            <Input
              type="number"
              min="1"
              max="365"
              placeholder={t('CameraAccessPanel.form.expiresPlaceholder')}
              value={expiresIn}
              onChange={(e) => setExpiresIn(e.target.value)}
              className="h-9 text-xs mt-1"
            />
          </div>
        </div>

        <div className="flex justify-end">
          <Button
            size="sm"
            className="gap-1.5"
            onClick={() => createMut.mutate()}
            disabled={!userId || createMut.isPending}
          >
            {createMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Shield className="h-4 w-4" />}
            {t('CameraAccessPanel.actions.grantAccess')}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
