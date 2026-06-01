// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikSnmpTab · SNMP server settings + trap-targets + SNMPv3 users.
 *
 * SECURITY: SNMPv3 passwords (auth + privacy) are write-only. They are
 * NEVER read back from the server, NEVER displayed in tables, NEVER
 * logged client-side. The create / update dialogs accept password
 * fields; we send them on submission and immediately clear local state.
 *
 * Three surfaces:
 *   - Card 1: SNMP server config (enabled, trap-community, contact,
 *     location) · single edit dialog that stages
 *     ``mikrotik.security.snmp.settings``.
 *   - Sub-table 1: Trap targets (address / port / version / community) ·
 *     full CRUD via ``mikrotik.security.snmp.trap_target``.
 *   - Sub-table 2: SNMPv3 users (name / auth-protocol / priv-protocol) ·
 *     full CRUD via ``mikrotik.security.snmp.v3_user``. Password fields
 *     are write-only, the table never shows a password column.
 */
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Activity,
  KeyRound,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  Send,
  Shield,
  Trash2,
  User,
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { useToast } from '@/hooks/use-toast';
import {
  getApiErrorMessage,
  mikrotikApi,
  type MikroTikSnmpTrapTarget,
  type MikroTikSnmpV3User,
} from '@/lib/api';

export interface MikroTikSnmpTabProps {
  controllerId: string;
  isActive: boolean;
}

const SETTINGS_KEY = (cid: string) => ['mikrotik', cid, 'snmp-settings'];
const TRAPS_KEY = (cid: string) => ['mikrotik', cid, 'snmp-traps'];
const V3_USERS_KEY = (cid: string) => ['mikrotik', cid, 'snmp-v3-users'];

const AUTH_PROTOCOLS = ['MD5', 'SHA1', 'SHA256', 'SHA512'];
const ENCRYPTION_PROTOCOLS = ['DES', 'AES', 'AES-192', 'AES-256'];
const TRAP_VERSIONS = ['1', '2', '3'];

type SettingsForm = {
  enabled: boolean;
  trapCommunity: string;
  contact: string;
  location: string;
};

type TrapForm = {
  address: string;
  port: string;
  version: string;
  community: string;
  comment: string;
};

type V3UserForm = {
  name: string;
  authProtocol: string;
  authPassword: string;
  encryptionProtocol: string;
  privacyPassword: string;
  addresses: string;
  comment: string;
};

const BLANK_SETTINGS: SettingsForm = {
  enabled: false,
  trapCommunity: '',
  contact: '',
  location: '',
};

const BLANK_TRAP: TrapForm = {
  address: '',
  port: '162',
  version: '2',
  community: '',
  comment: '',
};

const BLANK_V3_USER: V3UserForm = {
  name: '',
  authProtocol: 'SHA1',
  authPassword: '',
  encryptionProtocol: 'AES',
  privacyPassword: '',
  addresses: '',
  comment: '',
};

function asStr(value: unknown): string {
  if (value === undefined || value === null) return '-';
  if (typeof value === 'string') return value || '-';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return '-';
}

export function MikroTikSnmpTab({
  controllerId,
  isActive,
}: MikroTikSnmpTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const [settingsDialogOpen, setSettingsDialogOpen] = useState(false);
  const [settingsForm, setSettingsForm] = useState<SettingsForm>(BLANK_SETTINGS);

  const [trapDialogOpen, setTrapDialogOpen] = useState(false);
  const [editingTrap, setEditingTrap] = useState<MikroTikSnmpTrapTarget | null>(
    null,
  );
  const [trapForm, setTrapForm] = useState<TrapForm>(BLANK_TRAP);
  const [trapDeleteTarget, setTrapDeleteTarget] =
    useState<MikroTikSnmpTrapTarget | null>(null);

  const [v3UserDialogOpen, setV3UserDialogOpen] = useState(false);
  const [editingV3User, setEditingV3User] = useState<MikroTikSnmpV3User | null>(
    null,
  );
  const [v3UserForm, setV3UserForm] = useState<V3UserForm>(BLANK_V3_USER);
  const [v3UserDeleteTarget, setV3UserDeleteTarget] =
    useState<MikroTikSnmpV3User | null>(null);

  const trapsQuery = useQuery({
    queryKey: TRAPS_KEY(controllerId),
    queryFn: () => mikrotikApi.getSnmpTrapTargets(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const v3UsersQuery = useQuery({
    queryKey: V3_USERS_KEY(controllerId),
    queryFn: () => mikrotikApi.getSnmpV3Users(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const traps = trapsQuery.data?.data.items ?? [];
  // Backend returns a bare SNMPv3-user array (not an {items} envelope).
  const v3Users = v3UsersQuery.data?.data ?? [];

  // Seed the trap form whenever the dialog opens.
  useEffect(() => {
    if (trapDialogOpen && editingTrap) {
      setTrapForm({
        address: asStr(editingTrap.address) === '-' ? '' : asStr(editingTrap.address),
        port:
          asStr(editingTrap.port) === '-'
            ? '162'
            : asStr(editingTrap.port),
        version:
          asStr(editingTrap.version) === '-'
            ? '2'
            : asStr(editingTrap.version),
        community:
          asStr(editingTrap.community) === '-'
            ? ''
            : asStr(editingTrap.community),
        comment:
          asStr(editingTrap.comment) === '-' ? '' : asStr(editingTrap.comment),
      });
    } else if (trapDialogOpen && !editingTrap) {
      setTrapForm(BLANK_TRAP);
    }
  }, [trapDialogOpen, editingTrap]);

  // Seed the v3-user form whenever the dialog opens. PASSWORDS ARE
  // NEVER POPULATED ON EDIT, they're write-only and we cannot read
  // them back, so the operator must re-enter them only if rotating.
  useEffect(() => {
    if (v3UserDialogOpen && editingV3User) {
      setV3UserForm({
        name:
          asStr(editingV3User.name) === '-' ? '' : asStr(editingV3User.name),
        authProtocol:
          asStr(editingV3User['auth-protocol']) === '-'
            ? 'SHA1'
            : asStr(editingV3User['auth-protocol']),
        // NEVER populate from server data.
        authPassword: '',
        encryptionProtocol:
          asStr(editingV3User['encryption-protocol']) === '-'
            ? 'AES'
            : asStr(editingV3User['encryption-protocol']),
        // NEVER populate from server data.
        privacyPassword: '',
        addresses:
          asStr(editingV3User.addresses) === '-'
            ? ''
            : asStr(editingV3User.addresses),
        comment:
          asStr(editingV3User.comment) === '-'
            ? ''
            : asStr(editingV3User.comment),
      });
    } else if (v3UserDialogOpen && !editingV3User) {
      setV3UserForm(BLANK_V3_USER);
    }
  }, [v3UserDialogOpen, editingV3User]);

  const settingsMut = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      mikrotikApi.updateSnmpSettings(controllerId, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikSnmpTab.toasts.settingsStaged') });
      setSettingsDialogOpen(false);
      queryClient.invalidateQueries({ queryKey: SETTINGS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikSnmpTab.toasts.settingsFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const trapSaveMut = useMutation({
    mutationFn: (vars: { id: string | null; payload: Record<string, unknown> }) =>
      vars.id
        ? mikrotikApi.updateSnmpTrapTarget(controllerId, vars.id, vars.payload)
        : mikrotikApi.addSnmpTrapTarget(controllerId, vars.payload),
    onSuccess: () => {
      toast({ title: t('MikroTikSnmpTab.toasts.trapStaged') });
      setTrapDialogOpen(false);
      setEditingTrap(null);
      queryClient.invalidateQueries({ queryKey: TRAPS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikSnmpTab.toasts.trapFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const trapDeleteMut = useMutation({
    mutationFn: (id: string) =>
      mikrotikApi.removeSnmpTrapTarget(controllerId, id),
    onSuccess: () => {
      toast({ title: t('MikroTikSnmpTab.toasts.trapDeleteStaged') });
      setTrapDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: TRAPS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikSnmpTab.toasts.deleteFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const v3SaveMut = useMutation({
    mutationFn: (vars: { id: string | null; payload: Record<string, unknown> }) =>
      vars.id
        ? mikrotikApi.updateSnmpV3User(controllerId, vars.id, vars.payload)
        : mikrotikApi.addSnmpV3User(controllerId, vars.payload),
    onSuccess: () => {
      // Clear password fields immediately on success, defense in depth.
      setV3UserForm((f) => ({ ...f, authPassword: '', privacyPassword: '' }));
      toast({ title: t('MikroTikSnmpTab.toasts.v3UserStaged') });
      setV3UserDialogOpen(false);
      setEditingV3User(null);
      queryClient.invalidateQueries({ queryKey: V3_USERS_KEY(controllerId) });
    },
    onError: (err) => {
      // Clear passwords on error too, never let them linger in state.
      setV3UserForm((f) => ({ ...f, authPassword: '', privacyPassword: '' }));
      toast({
        title: t('MikroTikSnmpTab.toasts.v3UserFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const v3DeleteMut = useMutation({
    mutationFn: (id: string) =>
      mikrotikApi.deleteSnmpV3User(controllerId, id),
    onSuccess: () => {
      toast({ title: t('MikroTikSnmpTab.toasts.v3UserDeleteStaged') });
      setV3UserDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: V3_USERS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikSnmpTab.toasts.deleteFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  function submitSettings() {
    const payload: Record<string, unknown> = {
      enabled: settingsForm.enabled ? 'yes' : 'no',
    };
    if (settingsForm.trapCommunity.trim()) {
      payload['trap-community'] = settingsForm.trapCommunity.trim();
    }
    if (settingsForm.contact.trim()) payload.contact = settingsForm.contact.trim();
    if (settingsForm.location.trim()) payload.location = settingsForm.location.trim();
    settingsMut.mutate(payload);
  }

  function submitTrap() {
    const payload: Record<string, unknown> = {
      address: trapForm.address.trim(),
      port: trapForm.port.trim(),
      version: trapForm.version,
    };
    if (trapForm.community.trim()) payload.community = trapForm.community.trim();
    if (trapForm.comment.trim()) payload.comment = trapForm.comment.trim();
    trapSaveMut.mutate({
      id: editingTrap?.['.id'] ?? null,
      payload,
    });
  }

  function submitV3User() {
    const payload: Record<string, unknown> = {
      name: v3UserForm.name.trim(),
      'authentication-protocol': v3UserForm.authProtocol,
      'encryption-protocol': v3UserForm.encryptionProtocol,
    };
    if (v3UserForm.authPassword) {
      payload['authentication-password'] = v3UserForm.authPassword;
    }
    if (v3UserForm.privacyPassword) {
      payload['encryption-password'] = v3UserForm.privacyPassword;
    }
    if (v3UserForm.addresses.trim()) {
      payload.addresses = v3UserForm.addresses.trim();
    }
    if (v3UserForm.comment.trim()) {
      payload.comment = v3UserForm.comment.trim();
    }
    v3SaveMut.mutate({
      id: editingV3User?.['.id'] ?? null,
      payload,
    });
  }

  if (trapsQuery.isLoading && v3UsersQuery.isLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        {t('MikroTikSnmpTab.loading')}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            trapsQuery.refetch();
            v3UsersQuery.refetch();
          }}
        >
          <RefreshCw className="h-4 w-4 mr-1" /> {t('MikroTikSnmpTab.actions.refresh')}
        </Button>
      </div>

      {/* Card 1: SNMP server config */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-4 w-4" /> {t('MikroTikSnmpTab.server.title')}
              </CardTitle>
              <CardDescription>
                {t('MikroTikSnmpTab.server.description')}
              </CardDescription>
            </div>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setSettingsDialogOpen(true)}
            >
              <Pencil className="h-4 w-4 mr-1" aria-hidden="true" /> {t('MikroTikSnmpTab.actions.editSettings')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            {t('MikroTikSnmpTab.server.body')}
          </p>
        </CardContent>
      </Card>

      {/* Sub-table 1: Trap targets */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Send className="h-4 w-4" /> {t('MikroTikSnmpTab.traps.title')}
              </CardTitle>
              <CardDescription>
                {t('MikroTikSnmpTab.traps.description')}
              </CardDescription>
            </div>
            <Button
              size="sm"
              onClick={() => {
                setEditingTrap(null);
                setTrapDialogOpen(true);
              }}
            >
              <Plus className="h-4 w-4 mr-1" /> {t('MikroTikSnmpTab.actions.addTrap')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {trapsQuery.isError ? (
            <ErrorState
              message={getApiErrorMessage(
                trapsQuery.error,
                t('MikroTikSnmpTab.traps.loadError'),
              )}
              onRetry={() => trapsQuery.refetch()}
            />
          ) : traps.length === 0 ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikSnmpTab.traps.empty.title')}
              description={t('MikroTikSnmpTab.traps.empty.description')}
            />
          ) : (
            <div className="border rounded-md overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('MikroTikSnmpTab.traps.columns.address')}</TableHead>
                    <TableHead>{t('MikroTikSnmpTab.traps.columns.port')}</TableHead>
                    <TableHead>{t('MikroTikSnmpTab.traps.columns.version')}</TableHead>
                    <TableHead>{t('MikroTikSnmpTab.traps.columns.community')}</TableHead>
                    <TableHead>{t('MikroTikSnmpTab.traps.columns.comment')}</TableHead>
                    <TableHead className="text-right">{t('MikroTikSnmpTab.traps.columns.actions')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {traps.map((trap: MikroTikSnmpTrapTarget) => (
                    <TableRow key={trap['.id'] ?? asStr(trap.address)}>
                      <TableCell className="font-mono text-xs">
                        {asStr(trap.address)}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {asStr(trap.port)}
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">v{asStr(trap.version)}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {asStr(trap.community)}
                      </TableCell>
                      <TableCell className="text-xs">
                        {asStr(trap.comment)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              setEditingTrap(trap);
                              setTrapDialogOpen(true);
                            }}
                          >
                            <Pencil className="h-3 w-3 mr-1" aria-hidden="true" />
                            {t('MikroTikSnmpTab.actions.edit')}
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => setTrapDeleteTarget(trap)}
                          >
                            <Trash2 className="h-3 w-3 mr-1" aria-hidden="true" />
                            {t('MikroTikSnmpTab.actions.delete')}
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Sub-table 2: SNMPv3 users */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <User className="h-4 w-4" /> {t('MikroTikSnmpTab.v3Users.title')}
              </CardTitle>
              <CardDescription>
                {t('MikroTikSnmpTab.v3Users.description')}
              </CardDescription>
            </div>
            <Button
              size="sm"
              onClick={() => {
                setEditingV3User(null);
                setV3UserDialogOpen(true);
              }}
            >
              <Plus className="h-4 w-4 mr-1" /> {t('MikroTikSnmpTab.actions.addV3User')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {v3UsersQuery.isError ? (
            <ErrorState
              message={getApiErrorMessage(
                v3UsersQuery.error,
                t('MikroTikSnmpTab.v3Users.loadError'),
              )}
              onRetry={() => v3UsersQuery.refetch()}
            />
          ) : v3Users.length === 0 ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikSnmpTab.v3Users.empty.title')}
              description={t('MikroTikSnmpTab.v3Users.empty.description')}
            />
          ) : (
            <div className="border rounded-md overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('MikroTikSnmpTab.v3Users.columns.name')}</TableHead>
                    <TableHead>{t('MikroTikSnmpTab.v3Users.columns.authProtocol')}</TableHead>
                    <TableHead>{t('MikroTikSnmpTab.v3Users.columns.encryptionProtocol')}</TableHead>
                    <TableHead>{t('MikroTikSnmpTab.v3Users.columns.addresses')}</TableHead>
                    <TableHead className="text-right">{t('MikroTikSnmpTab.traps.columns.actions')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {v3Users.map((u: MikroTikSnmpV3User) => (
                    <TableRow key={u['.id'] ?? asStr(u.name)}>
                      <TableCell className="font-mono text-xs">
                        {asStr(u.name)}
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">
                          {asStr(u['auth-protocol'])}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">
                          {asStr(u['encryption-protocol'])}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {asStr(u.addresses)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              setEditingV3User(u);
                              setV3UserDialogOpen(true);
                            }}
                          >
                            <Pencil className="h-3 w-3 mr-1" aria-hidden="true" />
                            {t('MikroTikSnmpTab.actions.edit')}
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => setV3UserDeleteTarget(u)}
                          >
                            <Trash2 className="h-3 w-3 mr-1" aria-hidden="true" />
                            {t('MikroTikSnmpTab.actions.delete')}
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* SNMP settings dialog */}
      <Dialog
        open={settingsDialogOpen}
        onOpenChange={(open) => {
          if (!open) setSettingsDialogOpen(false);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('MikroTikSnmpTab.settingsDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikSnmpTab.settingsDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={settingsForm.enabled}
                onChange={(e) =>
                  setSettingsForm((f) => ({ ...f, enabled: e.target.checked }))
                }
              />
              {t('MikroTikSnmpTab.settingsDialog.enable')}
            </label>
            <div className="space-y-2">
              <Label htmlFor="mtk-snmp-trap-community">
                {t('MikroTikSnmpTab.settingsDialog.trapCommunity')}
              </Label>
              <Input
                id="mtk-snmp-trap-community"
                value={settingsForm.trapCommunity}
                onChange={(e) =>
                  setSettingsForm((f) => ({
                    ...f,
                    trapCommunity: e.target.value,
                  }))
                }
                placeholder="public"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-snmp-contact">{t('MikroTikSnmpTab.settingsDialog.contact')}</Label>
              <Input
                id="mtk-snmp-contact"
                value={settingsForm.contact}
                onChange={(e) =>
                  setSettingsForm((f) => ({ ...f, contact: e.target.value }))
                }
                placeholder="netops@example.com"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-snmp-location">{t('MikroTikSnmpTab.settingsDialog.location')}</Label>
              <Input
                id="mtk-snmp-location"
                value={settingsForm.location}
                onChange={(e) =>
                  setSettingsForm((f) => ({ ...f, location: e.target.value }))
                }
                placeholder={t('MikroTikSnmpTab.settingsDialog.locationPlaceholder')}
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setSettingsDialogOpen(false)}
            >
              {t('MikroTikSnmpTab.actions.cancel')}
            </Button>
            <Button onClick={submitSettings} disabled={settingsMut.isPending}>
              {settingsMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikSnmpTab.actions.stageUpdate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Trap target dialog */}
      <Dialog
        open={trapDialogOpen}
        onOpenChange={(open) => {
          if (!open) {
            setTrapDialogOpen(false);
            setEditingTrap(null);
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingTrap
                ? t('MikroTikSnmpTab.trapDialog.editTitle')
                : t('MikroTikSnmpTab.trapDialog.addTitle')}
            </DialogTitle>
            <DialogDescription>
              {t('MikroTikSnmpTab.trapDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mtk-trap-address">{t('MikroTikSnmpTab.trapDialog.address')}</Label>
              <Input
                id="mtk-trap-address"
                value={trapForm.address}
                onChange={(e) =>
                  setTrapForm((f) => ({ ...f, address: e.target.value }))
                }
                placeholder="10.0.0.1"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label htmlFor="mtk-trap-port">{t('MikroTikSnmpTab.trapDialog.port')}</Label>
                <Input
                  id="mtk-trap-port"
                  value={trapForm.port}
                  onChange={(e) =>
                    setTrapForm((f) => ({ ...f, port: e.target.value }))
                  }
                  placeholder="162"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="mtk-trap-version">{t('MikroTikSnmpTab.trapDialog.version')}</Label>
                <Select
                  value={trapForm.version}
                  onValueChange={(v) =>
                    setTrapForm((f) => ({ ...f, version: v }))
                  }
                >
                  <SelectTrigger id="mtk-trap-version">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TRAP_VERSIONS.map((v) => (
                      <SelectItem key={v} value={v}>
                        v{v}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-trap-community">{t('MikroTikSnmpTab.trapDialog.community')}</Label>
              <Input
                id="mtk-trap-community"
                value={trapForm.community}
                onChange={(e) =>
                  setTrapForm((f) => ({ ...f, community: e.target.value }))
                }
                placeholder="public"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-trap-comment">{t('MikroTikSnmpTab.trapDialog.comment')}</Label>
              <Input
                id="mtk-trap-comment"
                value={trapForm.comment}
                onChange={(e) =>
                  setTrapForm((f) => ({ ...f, comment: e.target.value }))
                }
                placeholder={t('MikroTikSnmpTab.trapDialog.commentPlaceholder')}
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setTrapDialogOpen(false);
                setEditingTrap(null);
              }}
            >
              {t('MikroTikSnmpTab.actions.cancel')}
            </Button>
            <Button
              onClick={submitTrap}
              disabled={!trapForm.address.trim() || trapSaveMut.isPending}
            >
              {trapSaveMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {editingTrap
                ? t('MikroTikSnmpTab.actions.stageUpdate')
                : t('MikroTikSnmpTab.actions.stageCreate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Trap delete confirmation */}
      <Dialog
        open={trapDeleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setTrapDeleteTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('MikroTikSnmpTab.trapDelete.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikSnmpTab.trapDelete.confirmPrefix')}{' '}
              <span className="font-mono">
                {trapDeleteTarget ? asStr(trapDeleteTarget.address) : ''}
              </span>
              {t('MikroTikSnmpTab.trapDelete.confirmSuffix')}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setTrapDeleteTarget(null)}
            >
              {t('MikroTikSnmpTab.actions.cancel')}
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                trapDeleteTarget?.['.id'] &&
                trapDeleteMut.mutate(trapDeleteTarget['.id'])
              }
              disabled={trapDeleteMut.isPending}
            >
              {trapDeleteMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikSnmpTab.actions.stageDelete')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* SNMPv3 user dialog · passwords are write-only */}
      <Dialog
        open={v3UserDialogOpen}
        onOpenChange={(open) => {
          if (!open) {
            setV3UserDialogOpen(false);
            setEditingV3User(null);
            // Always clear password fields on close, defense in depth.
            setV3UserForm((f) => ({
              ...f,
              authPassword: '',
              privacyPassword: '',
            }));
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <KeyRound className="h-4 w-4" />
              {editingV3User
                ? t('MikroTikSnmpTab.v3Dialog.editTitle')
                : t('MikroTikSnmpTab.v3Dialog.addTitle')}
            </DialogTitle>
            <DialogDescription>
              {t('MikroTikSnmpTab.v3Dialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mtk-v3-name">{t('MikroTikSnmpTab.v3Dialog.name')}</Label>
              <Input
                id="mtk-v3-name"
                value={v3UserForm.name}
                onChange={(e) =>
                  setV3UserForm((f) => ({ ...f, name: e.target.value }))
                }
                placeholder="monitor"
                disabled={!!editingV3User}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label htmlFor="mtk-v3-auth-proto">{t('MikroTikSnmpTab.v3Dialog.authProtocol')}</Label>
                <Select
                  value={v3UserForm.authProtocol}
                  onValueChange={(v) =>
                    setV3UserForm((f) => ({ ...f, authProtocol: v }))
                  }
                >
                  <SelectTrigger id="mtk-v3-auth-proto">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {AUTH_PROTOCOLS.map((p) => (
                      <SelectItem key={p} value={p}>
                        {p}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="mtk-v3-enc-proto">{t('MikroTikSnmpTab.v3Dialog.encryptionProtocol')}</Label>
                <Select
                  value={v3UserForm.encryptionProtocol}
                  onValueChange={(v) =>
                    setV3UserForm((f) => ({ ...f, encryptionProtocol: v }))
                  }
                >
                  <SelectTrigger id="mtk-v3-enc-proto">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ENCRYPTION_PROTOCOLS.map((p) => (
                      <SelectItem key={p} value={p}>
                        {p}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-v3-auth-pwd">{t('MikroTikSnmpTab.v3Dialog.authPassword')}</Label>
              <Input
                id="mtk-v3-auth-pwd"
                type="password"
                autoComplete="new-password"
                value={v3UserForm.authPassword}
                onChange={(e) =>
                  setV3UserForm((f) => ({
                    ...f,
                    authPassword: e.target.value,
                  }))
                }
                placeholder={
                  editingV3User
                    ? t('MikroTikSnmpTab.v3Dialog.passwordKeepPlaceholder')
                    : t('MikroTikSnmpTab.v3Dialog.passwordMinPlaceholder')
                }
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-v3-priv-pwd">{t('MikroTikSnmpTab.v3Dialog.privacyPassword')}</Label>
              <Input
                id="mtk-v3-priv-pwd"
                type="password"
                autoComplete="new-password"
                value={v3UserForm.privacyPassword}
                onChange={(e) =>
                  setV3UserForm((f) => ({
                    ...f,
                    privacyPassword: e.target.value,
                  }))
                }
                placeholder={
                  editingV3User
                    ? t('MikroTikSnmpTab.v3Dialog.passwordKeepPlaceholder')
                    : t('MikroTikSnmpTab.v3Dialog.passwordMinPlaceholder')
                }
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-v3-addresses">{t('MikroTikSnmpTab.v3Dialog.allowedAddresses')}</Label>
              <Input
                id="mtk-v3-addresses"
                value={v3UserForm.addresses}
                onChange={(e) =>
                  setV3UserForm((f) => ({ ...f, addresses: e.target.value }))
                }
                placeholder="0.0.0.0/0"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-v3-comment">{t('MikroTikSnmpTab.v3Dialog.comment')}</Label>
              <Input
                id="mtk-v3-comment"
                value={v3UserForm.comment}
                onChange={(e) =>
                  setV3UserForm((f) => ({ ...f, comment: e.target.value }))
                }
                placeholder={t('MikroTikSnmpTab.v3Dialog.commentPlaceholder')}
              />
            </div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Shield className="h-3 w-3" />
              {t('MikroTikSnmpTab.v3Dialog.securityNote')}
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setV3UserDialogOpen(false);
                setEditingV3User(null);
              }}
            >
              {t('MikroTikSnmpTab.actions.cancel')}
            </Button>
            <Button
              onClick={submitV3User}
              disabled={!v3UserForm.name.trim() || v3SaveMut.isPending}
            >
              {v3SaveMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {editingV3User
                ? t('MikroTikSnmpTab.actions.stageUpdate')
                : t('MikroTikSnmpTab.actions.stageCreate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* SNMPv3 user delete confirmation */}
      <Dialog
        open={v3UserDeleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setV3UserDeleteTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('MikroTikSnmpTab.v3Delete.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikSnmpTab.v3Delete.confirmPrefix')}{' '}
              <span className="font-mono">
                {v3UserDeleteTarget ? asStr(v3UserDeleteTarget.name) : ''}
              </span>
              {t('MikroTikSnmpTab.v3Delete.confirmSuffix')}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setV3UserDeleteTarget(null)}
            >
              {t('MikroTikSnmpTab.actions.cancel')}
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                v3UserDeleteTarget?.['.id'] &&
                v3DeleteMut.mutate(v3UserDeleteTarget['.id'])
              }
              disabled={v3DeleteMut.isPending}
            >
              {v3DeleteMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikSnmpTab.actions.stageDelete')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
