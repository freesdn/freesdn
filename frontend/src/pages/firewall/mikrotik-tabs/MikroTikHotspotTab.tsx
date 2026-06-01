// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikHotspotTab · RouterOS captive-portal Hotspot servers,
 * user-profiles, active sessions.
 *
 * Three sub-tables:
 * - Servers (``/ip/hotspot``): per-interface server binding. Full CRUD
 *   via stage (``mikrotik.hotspot.server``).
 * - User profiles (``/ip/hotspot/user/profile``): rate / quota /
 *   keepalive templates. Full CRUD via stage
 *   (``mikrotik.hotspot.user_profile``).
 * - Active users (``/ip/hotspot/active``): read-only. Each row has a
 *   "Disconnect" action that's disabled because the adapter
 *   doesn't expose ``delete_hotspot_active`` yet, the button surfaces
 *   the gap to operators without crashing. Wiring the disconnect
 *   client method is planned for a later release.
 *
 * Note: this is the *captive portal* feature, not WiFi authentication.
 * It's most often used for guest networks. The user-profile rate limits
 * are kbit/s tokens (RouterOS quirk), operators should test before
 * trusting a freshly staged limit.
 */
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
  UserCheck,
  Users,
  Wifi,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { useToast } from '@/hooks/use-toast';
import {
  getApiErrorMessage,
  mikrotikApi,
  type MikroTikHotspotServer,
  type MikroTikHotspotUserProfile,
} from '@/lib/api';
import { getRouterId } from './_shared';

export interface MikroTikHotspotTabProps {
  controllerId: string;
  isActive: boolean;
  /** Display name of the controller, surfaced in error toasts. */
  gatewayName?: string;
}

const SERVERS_KEY = (cid: string) => ['mikrotik', cid, 'hotspot-servers'];
const PROFILES_KEY = (cid: string) => ['mikrotik', cid, 'hotspot-user-profiles'];
const ACTIVE_KEY = (cid: string) => ['mikrotik', cid, 'hotspot-active'];

type ServerForm = {
  name: string;
  iface: string;
  pool: string;
  profile: string;
  comment: string;
};

type ProfileForm = {
  name: string;
  rateLimit: string;
  sessionTimeout: string;
  idleTimeout: string;
  sharedUsers: string;
};

const BLANK_SERVER: ServerForm = {
  name: '',
  iface: '',
  pool: '',
  profile: '',
  comment: '',
};

const BLANK_PROFILE: ProfileForm = {
  name: '',
  rateLimit: '',
  sessionTimeout: '',
  idleTimeout: '',
  sharedUsers: '',
};

function asStr(value: unknown): string {
  if (value === undefined || value === null) return '-';
  if (typeof value === 'string') return value || '-';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return '-';
}

function asBool(value: unknown): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') return value === 'true' || value === 'yes';
  return false;
}

type DeleteTarget =
  | { kind: 'server'; row: MikroTikHotspotServer }
  | { kind: 'profile'; row: MikroTikHotspotUserProfile };

export function MikroTikHotspotTab({
  controllerId,
  isActive,
  gatewayName,
}: MikroTikHotspotTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const ctx = gatewayName ? `${gatewayName}: ` : '';

  const [serverFormOpen, setServerFormOpen] = useState(false);
  const [editingServer, setEditingServer] =
    useState<MikroTikHotspotServer | null>(null);
  const [serverForm, setServerForm] = useState<ServerForm>(BLANK_SERVER);

  const [profileFormOpen, setProfileFormOpen] = useState(false);
  const [editingProfile, setEditingProfile] =
    useState<MikroTikHotspotUserProfile | null>(null);
  const [profileForm, setProfileForm] = useState<ProfileForm>(BLANK_PROFILE);

  const [deleteTarget, setDeleteTarget] = useState<DeleteTarget | null>(null);

  const servers = useQuery({
    queryKey: SERVERS_KEY(controllerId),
    queryFn: () => mikrotikApi.getHotspotServers(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const profiles = useQuery({
    queryKey: PROFILES_KEY(controllerId),
    queryFn: () => mikrotikApi.getHotspotUserProfiles(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const active = useQuery({
    queryKey: ACTIVE_KEY(controllerId),
    queryFn: () => mikrotikApi.getHotspotActive(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 15_000,
  });

  // MEDIUM-4: memoise so dependent consumers don't see a fresh array
  // identity every render (would otherwise force `key` reuse + churn
  // through the active-sessions virtual list when adds it).
  const serverRows: MikroTikHotspotServer[] = useMemo(
    () => servers.data?.data.items ?? [],
    [servers.data],
  );
  const profileRows: MikroTikHotspotUserProfile[] = useMemo(
    () => profiles.data?.data.items ?? [],
    [profiles.data],
  );
  const activeRows = useMemo(
    () => active.data?.data.items ?? [],
    [active.data],
  );

  // ── Mutations ────────────────────────────────────────────────────
  const createServerMut = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      mikrotikApi.createHotspotServer(controllerId, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikHotspotTab.toasts.serverCreateStaged') });
      setServerFormOpen(false);
      queryClient.invalidateQueries({ queryKey: SERVERS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikHotspotTab.toasts.serverCreateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const updateServerMut = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      mikrotikApi.updateHotspotServer(controllerId, id, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikHotspotTab.toasts.serverUpdateStaged') });
      setServerFormOpen(false);
      queryClient.invalidateQueries({ queryKey: SERVERS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikHotspotTab.toasts.serverUpdateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const deleteServerMut = useMutation({
    mutationFn: (id: string) => mikrotikApi.deleteHotspotServer(controllerId, id),
    onSuccess: () => {
      toast({ title: t('MikroTikHotspotTab.toasts.serverDeleteStaged') });
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: SERVERS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikHotspotTab.toasts.serverDeleteFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const createProfileMut = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      mikrotikApi.createHotspotUserProfile(controllerId, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikHotspotTab.toasts.profileCreateStaged') });
      setProfileFormOpen(false);
      queryClient.invalidateQueries({ queryKey: PROFILES_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikHotspotTab.toasts.profileCreateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const updateProfileMut = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      mikrotikApi.updateHotspotUserProfile(controllerId, id, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikHotspotTab.toasts.profileUpdateStaged') });
      setProfileFormOpen(false);
      queryClient.invalidateQueries({ queryKey: PROFILES_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikHotspotTab.toasts.profileUpdateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const deleteProfileMut = useMutation({
    mutationFn: (id: string) => mikrotikApi.deleteHotspotUserProfile(controllerId, id),
    onSuccess: () => {
      toast({ title: t('MikroTikHotspotTab.toasts.profileDeleteStaged') });
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: PROFILES_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikHotspotTab.toasts.profileDeleteFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  // ── Form helpers ─────────────────────────────────────────────────
  function openNewServer() {
    setEditingServer(null);
    setServerForm(BLANK_SERVER);
    setServerFormOpen(true);
  }

  function openEditServer(row: MikroTikHotspotServer) {
    setEditingServer(row);
    setServerForm({
      name: typeof row.name === 'string' ? row.name : '',
      iface: typeof row.interface === 'string' ? row.interface : '',
      pool: typeof row['address-pool'] === 'string' ? row['address-pool'] : '',
      profile: typeof row.profile === 'string' ? row.profile : '',
      comment: typeof row.comment === 'string' ? row.comment : '',
    });
    setServerFormOpen(true);
  }

  function submitServer() {
    const trimmed = {
      name: serverForm.name.trim(),
      iface: serverForm.iface.trim(),
      pool: serverForm.pool.trim(),
      profile: serverForm.profile.trim(),
      comment: serverForm.comment.trim(),
    };
    if (!trimmed.name || !trimmed.iface) return;
    const payload: Record<string, unknown> = {
      name: trimmed.name,
      interface: trimmed.iface,
    };
    if (trimmed.pool) payload['address-pool'] = trimmed.pool;
    if (trimmed.profile) payload.profile = trimmed.profile;
    if (trimmed.comment) payload.comment = trimmed.comment;

    if (editingServer) {
      const id = getRouterId(editingServer);
      if (!id) {
        toast({
          title: t('MikroTikHotspotTab.errors.cannotUpdateServerTitle'),
          description: t('MikroTikHotspotTab.errors.serverNoId'),
          variant: 'destructive',
        });
        return;
      }
      updateServerMut.mutate({ id, payload });
    } else {
      createServerMut.mutate(payload);
    }
  }

  function openNewProfile() {
    setEditingProfile(null);
    setProfileForm(BLANK_PROFILE);
    setProfileFormOpen(true);
  }

  function openEditProfile(row: MikroTikHotspotUserProfile) {
    setEditingProfile(row);
    setProfileForm({
      name: typeof row.name === 'string' ? row.name : '',
      rateLimit: typeof row['rate-limit'] === 'string' ? row['rate-limit'] : '',
      sessionTimeout:
        typeof row['session-timeout'] === 'string' ? row['session-timeout'] : '',
      idleTimeout:
        typeof row['idle-timeout'] === 'string' ? row['idle-timeout'] : '',
      sharedUsers:
        typeof row['shared-users'] === 'string'
          ? row['shared-users']
          : typeof row['shared-users'] === 'number'
            ? String(row['shared-users'])
            : '',
    });
    setProfileFormOpen(true);
  }

  function submitProfile() {
    const trimmed = {
      name: profileForm.name.trim(),
      rateLimit: profileForm.rateLimit.trim(),
      sessionTimeout: profileForm.sessionTimeout.trim(),
      idleTimeout: profileForm.idleTimeout.trim(),
      sharedUsers: profileForm.sharedUsers.trim(),
    };
    if (!trimmed.name) return;
    const payload: Record<string, unknown> = { name: trimmed.name };
    if (trimmed.rateLimit) payload['rate-limit'] = trimmed.rateLimit;
    if (trimmed.sessionTimeout) payload['session-timeout'] = trimmed.sessionTimeout;
    if (trimmed.idleTimeout) payload['idle-timeout'] = trimmed.idleTimeout;
    if (trimmed.sharedUsers) payload['shared-users'] = trimmed.sharedUsers;

    if (editingProfile) {
      const id = getRouterId(editingProfile);
      if (!id) {
        toast({
          title: t('MikroTikHotspotTab.errors.cannotUpdateProfileTitle'),
          description: t('MikroTikHotspotTab.errors.profileNoId'),
          variant: 'destructive',
        });
        return;
      }
      updateProfileMut.mutate({ id, payload });
    } else {
      createProfileMut.mutate(payload);
    }
  }

  function submitDelete() {
    if (!deleteTarget) return;
    const id = getRouterId(deleteTarget.row);
    if (!id) {
      toast({
        title: t('MikroTikHotspotTab.errors.cannotDeleteTitle'),
        description: t('MikroTikHotspotTab.errors.rowNoId'),
        variant: 'destructive',
      });
      return;
    }
    if (deleteTarget.kind === 'server') deleteServerMut.mutate(id);
    else deleteProfileMut.mutate(id);
  }

  if (servers.isLoading && profiles.isLoading && active.isLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        {t('MikroTikHotspotTab.loading')}
      </div>
    );
  }

  const deleteLabel = (() => {
    if (!deleteTarget) return '';
    if (deleteTarget.kind === 'server') {
      const row = deleteTarget.row as MikroTikHotspotServer;
      return t('MikroTikHotspotTab.deleteLabel.server', { name: asStr(row.name) });
    }
    const row = deleteTarget.row as MikroTikHotspotUserProfile;
    return t('MikroTikHotspotTab.deleteLabel.profile', { name: asStr(row.name) });
  })();

  const anyFetching = servers.isFetching || profiles.isFetching || active.isFetching;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <Button
          variant="outline"
          size="sm"
          disabled={anyFetching}
          onClick={() => {
            servers.refetch();
            profiles.refetch();
            active.refetch();
          }}
        >
          {anyFetching ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <RefreshCw className="h-4 w-4 mr-1" />
          )}
          {t('MikroTikHotspotTab.actions.refresh')}
        </Button>
      </div>

      {/* Servers */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Wifi className="h-4 w-4" /> {t('MikroTikHotspotTab.servers.title')}
              </CardTitle>
              <CardDescription>
                ``/ip/hotspot`` {t('MikroTikHotspotTab.servers.description')}
              </CardDescription>
            </div>
            <Button size="sm" onClick={openNewServer}>
              <Plus className="h-4 w-4 mr-1" /> {t('MikroTikHotspotTab.actions.addServer')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {servers.isError ? (
            <ErrorState
              message={getApiErrorMessage(servers.error, t('MikroTikHotspotTab.servers.loadError'))}
              onRetry={() => servers.refetch()}
            />
          ) : serverRows.length === 0 && !servers.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikHotspotTab.servers.emptyTitle')}
              description={t('MikroTikHotspotTab.servers.emptyDescription')}
              action={{ label: t('MikroTikHotspotTab.actions.addServer'), icon: Plus, onClick: openNewServer }}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikHotspotTab.columns.name')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikHotspotTab.columns.interface')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikHotspotTab.columns.pool')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikHotspotTab.columns.profile')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikHotspotTab.columns.enabled')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikHotspotTab.columns.comment')}</th>
                    <th className="px-3 py-2 font-medium text-right">{t('MikroTikHotspotTab.columns.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {serverRows.map((row) => {
                    const id = getRouterId(row);
                    const enabled = !asBool(row.disabled);
                    const serverLabel = asStr(row.name) !== '-' ? asStr(row.name) : id || t('MikroTikHotspotTab.fallback.server');
                    return (
                      <tr key={id || row.name || Math.random()} className="border-b last:border-0">
                        <td className="px-3 py-2 font-medium">{asStr(row.name)}</td>
                        <td className="px-3 py-2">{asStr(row.interface)}</td>
                        <td className="px-3 py-2">{asStr(row['address-pool'])}</td>
                        <td className="px-3 py-2">{asStr(row.profile)}</td>
                        <td className="px-3 py-2">
                          <Badge variant={enabled ? 'default' : 'secondary'}>
                            {enabled ? t('MikroTikHotspotTab.common.yes') : t('MikroTikHotspotTab.common.no')}
                          </Badge>
                        </td>
                        <td className="px-3 py-2 text-xs text-muted-foreground">{asStr(row.comment)}</td>
                        <td className="px-3 py-2 text-right">
                          <div className="flex items-center gap-1 justify-end">
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id}
                              aria-label={t('MikroTikHotspotTab.aria.editServer', { name: serverLabel })}
                              onClick={() => openEditServer(row)}
                            >
                              <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id}
                              aria-label={t('MikroTikHotspotTab.aria.deleteServer', { name: serverLabel })}
                              onClick={() => setDeleteTarget({ kind: 'server', row })}
                            >
                              <Trash2 className="h-3.5 w-3.5 text-destructive" aria-hidden="true" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* User profiles */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Users className="h-4 w-4" /> {t('MikroTikHotspotTab.profiles.title')}
              </CardTitle>
              <CardDescription>
                ``/ip/hotspot/user/profile`` {t('MikroTikHotspotTab.profiles.description')}
              </CardDescription>
            </div>
            <Button size="sm" onClick={openNewProfile}>
              <Plus className="h-4 w-4 mr-1" /> {t('MikroTikHotspotTab.actions.addProfile')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {profiles.isError ? (
            <ErrorState
              message={getApiErrorMessage(profiles.error, t('MikroTikHotspotTab.profiles.loadError'))}
              onRetry={() => profiles.refetch()}
            />
          ) : profileRows.length === 0 && !profiles.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikHotspotTab.profiles.emptyTitle')}
              description={t('MikroTikHotspotTab.profiles.emptyDescription')}
              action={{ label: t('MikroTikHotspotTab.actions.addProfile'), icon: Plus, onClick: openNewProfile }}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikHotspotTab.columns.name')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikHotspotTab.columns.rateLimit')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikHotspotTab.columns.sessionTimeout')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikHotspotTab.columns.idleTimeout')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikHotspotTab.columns.sharedUsers')}</th>
                    <th className="px-3 py-2 font-medium text-right">{t('MikroTikHotspotTab.columns.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {profileRows.map((row) => {
                    const id = getRouterId(row);
                    const profileLabel = asStr(row.name) !== '-' ? asStr(row.name) : id || t('MikroTikHotspotTab.fallback.profile');
                    return (
                      <tr key={id || row.name || Math.random()} className="border-b last:border-0">
                        <td className="px-3 py-2 font-medium">
                          {asStr(row.name)}
                          {asBool(row.default) && (
                            <Badge variant="secondary" className="ml-2">
                              {t('MikroTikHotspotTab.common.default')}
                            </Badge>
                          )}
                        </td>
                        <td className="px-3 py-2 font-mono text-xs">{asStr(row['rate-limit'])}</td>
                        <td className="px-3 py-2">{asStr(row['session-timeout'])}</td>
                        <td className="px-3 py-2">{asStr(row['idle-timeout'])}</td>
                        <td className="px-3 py-2">{asStr(row['shared-users'])}</td>
                        <td className="px-3 py-2 text-right">
                          <div className="flex items-center gap-1 justify-end">
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id || asBool(row.default)}
                              aria-label={t('MikroTikHotspotTab.aria.editProfile', { name: profileLabel })}
                              onClick={() => openEditProfile(row)}
                            >
                              <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id || asBool(row.default)}
                              aria-label={t('MikroTikHotspotTab.aria.deleteProfile', { name: profileLabel })}
                              onClick={() => setDeleteTarget({ kind: 'profile', row })}
                            >
                              <Trash2 className="h-3.5 w-3.5 text-destructive" aria-hidden="true" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Active users (read-only + disconnect, disconnect deferred) */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2">
            <UserCheck className="h-4 w-4" /> {t('MikroTikHotspotTab.active.title')}
          </CardTitle>
          <CardDescription>
            ``/ip/hotspot/active`` {t('MikroTikHotspotTab.active.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {active.isError ? (
            <ErrorState
              message={getApiErrorMessage(active.error, t('MikroTikHotspotTab.active.loadError'))}
              onRetry={() => active.refetch()}
            />
          ) : activeRows.length === 0 && !active.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikHotspotTab.active.emptyTitle')}
              description={t('MikroTikHotspotTab.active.emptyDescription')}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikHotspotTab.columns.user')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikHotspotTab.columns.ip')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikHotspotTab.columns.mac')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikHotspotTab.columns.uptime')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikHotspotTab.columns.server')}</th>
                    <th className="px-3 py-2 font-medium text-right">{t('MikroTikHotspotTab.columns.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {activeRows.map((row, idx) => {
                    const id = getRouterId(row) || String(idx);
                    return (
                      <tr key={id} className="border-b last:border-0">
                        <td className="px-3 py-2 font-medium">{asStr(row.user)}</td>
                        <td className="px-3 py-2 font-mono">{asStr(row.address)}</td>
                        <td className="px-3 py-2 font-mono text-xs">{asStr(row['mac-address'])}</td>
                        <td className="px-3 py-2">{asStr(row.uptime)}</td>
                        <td className="px-3 py-2">{asStr(row.server)}</td>
                        <td className="px-3 py-2 text-right">
                          <Button
                            variant="outline"
                            size="sm"
                            disabled
                            title={t('MikroTikHotspotTab.active.disconnectTooltip')}
                          >
                            {t('MikroTikHotspotTab.active.disconnect')}
                          </Button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Server form dialog */}
      <Dialog open={serverFormOpen} onOpenChange={setServerFormOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingServer
                ? t('MikroTikHotspotTab.serverDialog.editTitle')
                : t('MikroTikHotspotTab.serverDialog.addTitle')}
            </DialogTitle>
            <DialogDescription>
              {t('MikroTikHotspotTab.serverDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mtk-hs-name">{t('MikroTikHotspotTab.fields.name')}</Label>
              <Input
                id="mtk-hs-name"
                value={serverForm.name}
                onChange={(e) => setServerForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="guest-hotspot"
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-hs-iface">{t('MikroTikHotspotTab.fields.interface')}</Label>
              <Input
                id="mtk-hs-iface"
                value={serverForm.iface}
                onChange={(e) => setServerForm((f) => ({ ...f, iface: e.target.value }))}
                placeholder="bridge-guest"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-hs-pool">{t('MikroTikHotspotTab.fields.addressPool')}</Label>
              <Input
                id="mtk-hs-pool"
                value={serverForm.pool}
                onChange={(e) => setServerForm((f) => ({ ...f, pool: e.target.value }))}
                placeholder="hs-pool"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-hs-profile">{t('MikroTikHotspotTab.fields.profile')}</Label>
              <Input
                id="mtk-hs-profile"
                value={serverForm.profile}
                onChange={(e) => setServerForm((f) => ({ ...f, profile: e.target.value }))}
                placeholder="default"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-hs-comment">{t('MikroTikHotspotTab.fields.comment')}</Label>
              <Input
                id="mtk-hs-comment"
                value={serverForm.comment}
                onChange={(e) => setServerForm((f) => ({ ...f, comment: e.target.value }))}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setServerFormOpen(false)}>
              {t('MikroTikHotspotTab.actions.cancel')}
            </Button>
            <Button
              onClick={submitServer}
              disabled={
                createServerMut.isPending ||
                updateServerMut.isPending ||
                serverForm.name.trim().length === 0 ||
                serverForm.iface.trim().length === 0
              }
            >
              {(createServerMut.isPending || updateServerMut.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {editingServer
                ? t('MikroTikHotspotTab.actions.stageUpdate')
                : t('MikroTikHotspotTab.actions.stageCreate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Profile form dialog */}
      <Dialog open={profileFormOpen} onOpenChange={setProfileFormOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingProfile
                ? t('MikroTikHotspotTab.profileDialog.editTitle')
                : t('MikroTikHotspotTab.profileDialog.addTitle')}
            </DialogTitle>
            <DialogDescription>
              {t('MikroTikHotspotTab.profileDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mtk-hp-name">{t('MikroTikHotspotTab.fields.name')}</Label>
              <Input
                id="mtk-hp-name"
                value={profileForm.name}
                onChange={(e) => setProfileForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="guest-1m"
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-hp-rate">{t('MikroTikHotspotTab.fields.rateLimit')}</Label>
              <Input
                id="mtk-hp-rate"
                value={profileForm.rateLimit}
                onChange={(e) =>
                  setProfileForm((f) => ({ ...f, rateLimit: e.target.value }))
                }
                placeholder="1M/2M"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-hp-session">{t('MikroTikHotspotTab.fields.sessionTimeout')}</Label>
              <Input
                id="mtk-hp-session"
                value={profileForm.sessionTimeout}
                onChange={(e) =>
                  setProfileForm((f) => ({ ...f, sessionTimeout: e.target.value }))
                }
                placeholder="1h"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-hp-idle">{t('MikroTikHotspotTab.fields.idleTimeout')}</Label>
              <Input
                id="mtk-hp-idle"
                value={profileForm.idleTimeout}
                onChange={(e) =>
                  setProfileForm((f) => ({ ...f, idleTimeout: e.target.value }))
                }
                placeholder="00:05:00"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-hp-shared">{t('MikroTikHotspotTab.fields.sharedUsers')}</Label>
              <Input
                id="mtk-hp-shared"
                value={profileForm.sharedUsers}
                onChange={(e) =>
                  setProfileForm((f) => ({ ...f, sharedUsers: e.target.value }))
                }
                placeholder="1"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setProfileFormOpen(false)}>
              {t('MikroTikHotspotTab.actions.cancel')}
            </Button>
            <Button
              onClick={submitProfile}
              disabled={
                createProfileMut.isPending ||
                updateProfileMut.isPending ||
                profileForm.name.trim().length === 0
              }
            >
              {(createProfileMut.isPending || updateProfileMut.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {editingProfile
                ? t('MikroTikHotspotTab.actions.stageUpdate')
                : t('MikroTikHotspotTab.actions.stageCreate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation */}
      <Dialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('MikroTikHotspotTab.deleteDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikHotspotTab.deleteDialog.intro')}{' '}
              <span className="font-mono">{deleteLabel}</span>.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              {t('MikroTikHotspotTab.actions.cancel')}
            </Button>
            <Button
              variant="destructive"
              disabled={deleteServerMut.isPending || deleteProfileMut.isPending}
              onClick={submitDelete}
            >
              {(deleteServerMut.isPending || deleteProfileMut.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikHotspotTab.actions.stageDelete')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
