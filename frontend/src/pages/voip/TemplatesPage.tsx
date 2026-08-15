// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Config Templates Page
 *
 * CRUD for provisioning config templates with:
 *  - Template list / DataTable
 *  - Create / Edit dialog with SIP, network, custom settings JSON
 *  - Vendor / model targeting
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import {
  FileText, Plus, Pencil, Trash2, Copy, Settings, AlertTriangle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuTrigger, DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu';
import { voipApi } from '@/lib/api';
import { PageHeader } from '@/components/layout';
import { useToast } from '@/hooks/use-toast';
import { VendorLabel, formatTimeAgo } from './components';
import type { ConfigTemplate } from './types';

interface TemplateForm {
  name: string;
  description: string;
  vendor: string;
  model_pattern: string;
  is_default: boolean;
  sip_settings: string;
  network_settings: string;
}

const emptyForm: TemplateForm = {
  name: '',
  description: '',
  vendor: 'grandstream',
  model_pattern: '',
  is_default: false,
  sip_settings: '{}',
  network_settings: '{}',
};

function tryParseJSON(val: string): object | null {
  try { return JSON.parse(val); } catch { return null; }
}

export default function TemplatesPage() {
  const { t } = useTranslation('voip');
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const [showDialog, setShowDialog] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<TemplateForm>({ ...emptyForm });

  // Site context
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ── Queries ──

  const { data: templatesRes, isLoading, isError, refetch } = useQuery({
    queryKey: ['voip-templates', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getTemplates({ limit: 200, site_id: selectedSiteId ?? undefined }),
    staleTime: 30_000,
  });

  const templates: ConfigTemplate[] = templatesRes?.data?.items ?? [];

  // ── Mutations ──

  const createMutation = useMutation({
    mutationFn: (data: any) => voipApi.createTemplate(data),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['voip-templates'] }); closeDialog(); },
    onError: (err: any) => { toast({ title: t('VoipTemplatesPage.toast.errorTitle'), description: err?.response?.data?.detail || t('VoipTemplatesPage.toast.createFailed'), variant: 'destructive' }); },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => voipApi.updateTemplate(id, data),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['voip-templates'] }); closeDialog(); },
    onError: (err: any) => { toast({ title: t('VoipTemplatesPage.toast.errorTitle'), description: err?.response?.data?.detail || t('VoipTemplatesPage.toast.updateFailed'), variant: 'destructive' }); },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => voipApi.deleteTemplate(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['voip-templates'] }),
    onError: (err: any) => { toast({ title: t('VoipTemplatesPage.toast.errorTitle'), description: err?.response?.data?.detail || t('VoipTemplatesPage.toast.deleteFailed'), variant: 'destructive' }); },
  });

  // ── Helpers ──

  function openCreate() {
    setEditingId(null);
    setForm({ ...emptyForm });
    setShowDialog(true);
  }

  function openEdit(t: ConfigTemplate) {
    setEditingId(t.id);
    setForm({
      name: t.name,
      description: t.description || '',
      vendor: t.vendor || 'grandstream',
      model_pattern: t.model_pattern || '',
      is_default: t.is_default ?? false,
      sip_settings: JSON.stringify(t.sip_settings || {}, null, 2),
      network_settings: JSON.stringify(t.network_settings || {}, null, 2),
    });
    setShowDialog(true);
  }

  function closeDialog() {
    setShowDialog(false);
    setEditingId(null);
    setForm({ ...emptyForm });
  }

  function handleSave() {
    const payload = {
      name: form.name,
      description: form.description || undefined,
      vendor: form.vendor,
      model_pattern: form.model_pattern || undefined,
      is_default: form.is_default,
      sip_settings: tryParseJSON(form.sip_settings) || {},
      network_settings: tryParseJSON(form.network_settings) || {},
    };
    if (editingId) {
      updateMutation.mutate({ id: editingId, data: payload });
    } else {
      createMutation.mutate({ ...payload, site_id: selectedSiteId ?? undefined });
    }
  }

  // ── Column Defs ──

  const columns: DataTableColumn<ConfigTemplate>[] = [
    {
      id: 'name',
      header: t('VoipTemplatesPage.columns.template'),
      cell: (row) => (
        <div className="flex flex-col">
          <div className="flex items-center gap-2">
            <span className="font-medium">{row.name}</span>
            {row.is_default && <Badge variant="secondary" className="text-xs">{t('VoipTemplatesPage.badges.default')}</Badge>}
          </div>
          {row.description && (
            <span className="text-xs text-muted-foreground truncate max-w-[300px]">{row.description}</span>
          )}
        </div>
      ),
      sortable: true,
    },
    {
      id: 'vendor',
      header: t('VoipTemplatesPage.columns.vendor'),
      cell: (row) => <VendorLabel vendor={row.vendor} />,
    },
    {
      id: 'model_pattern',
      header: t('VoipTemplatesPage.columns.modelPattern'),
      cell: (row) => <span className="text-sm font-mono">{row.model_pattern || '*'}</span>,
    },
    {
      id: 'phones_using',
      header: t('VoipTemplatesPage.columns.phones'),
      cell: (row) => <Badge variant="outline">{row.phones_count ?? 0}</Badge>,
    },
    {
      id: 'updated',
      header: t('VoipTemplatesPage.columns.updated'),
      cell: (row) => <span className="text-sm text-muted-foreground">{formatTimeAgo(row.updated_at)}</span>,
    },
    {
      id: 'actions',
      header: '',
      cell: (row) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <Settings className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => openEdit(row)}>
              <Pencil className="h-4 w-4 mr-2" /> {t('VoipTemplatesPage.actions.edit')}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => {
              setEditingId(null);
              setForm({
                ...emptyForm,
                name: t('VoipTemplatesPage.duplicateName', { name: row.name }),
                vendor: row.vendor || 'grandstream',
                model_pattern: row.model_pattern || '',
                sip_settings: JSON.stringify(row.sip_settings || {}, null, 2),
                network_settings: JSON.stringify(row.network_settings || {}, null, 2),
              });
              setShowDialog(true);
            }}>
              <Copy className="h-4 w-4 mr-2" /> {t('VoipTemplatesPage.actions.duplicate')}
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => deleteMutation.mutate(row.id)} className="text-red-500">
              <Trash2 className="h-4 w-4 mr-2" /> {t('VoipTemplatesPage.actions.delete')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ];

  const sipValid = tryParseJSON(form.sip_settings) !== null;
  const netValid = tryParseJSON(form.network_settings) !== null;
  const formValid = form.name.trim() && sipValid && netValid;

  return (
    <div className="space-y-6">
      <PageHeader
        icon={FileText}
        title={t('VoipTemplatesPage.header.title')}
        subtitle={t('VoipTemplatesPage.header.subtitle', { count: templates.length })}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        primaryAction={{ label: t('VoipTemplatesPage.actions.newTemplate'), icon: Plus, onClick: openCreate }}
      />

      {isError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('VoipTemplatesPage.errorBanner')}</span>
          </CardContent>
        </Card>
      )}

      <DataTable
        data={templates}
        columns={columns}
        isLoading={isLoading}
        searchable
        itemName={t('VoipTemplatesPage.itemName')}
        paginated
        defaultPageSize={15}
        emptyState={
          <div className="flex flex-col items-center gap-3 py-12">
            <FileText className="h-12 w-12 text-muted-foreground/30" />
            <p className="text-muted-foreground">{t('VoipTemplatesPage.empty.title')}</p>
            <Button onClick={openCreate}>
              <Plus className="h-4 w-4 mr-2" /> {t('VoipTemplatesPage.empty.createFirst')}
            </Button>
          </div>
        }
      />

      {/* Create/Edit Dialog */}
      <Dialog open={showDialog} onOpenChange={setShowDialog}>
        <DialogContent className="sm:max-w-[700px] max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editingId ? t('VoipTemplatesPage.dialog.editTitle') : t('VoipTemplatesPage.dialog.createTitle')}</DialogTitle>
            <DialogDescription>
              {editingId ? t('VoipTemplatesPage.dialog.editDescription') : t('VoipTemplatesPage.dialog.createDescription')}
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-4">
            {/* Basic Info */}
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label>{t('VoipTemplatesPage.form.nameLabel')}</Label>
                <Input placeholder={t('VoipTemplatesPage.form.namePlaceholder')} value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })} />
              </div>
              <div className="grid gap-2">
                <Label>{t('VoipTemplatesPage.form.vendorLabel')}</Label>
                <Select value={form.vendor} onValueChange={(v) => setForm({ ...form, vendor: v })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="grandstream">Grandstream</SelectItem>
                    <SelectItem value="yealink">Yealink</SelectItem>
                    <SelectItem value="polycom">Polycom</SelectItem>
                    <SelectItem value="cisco">Cisco</SelectItem>
                    <SelectItem value="fanvil">Fanvil</SelectItem>
                    <SelectItem value="generic">{t('VoipTemplatesPage.vendors.generic')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label>{t('VoipTemplatesPage.form.modelPatternLabel')}</Label>
                <Input placeholder="GRP26*" value={form.model_pattern}
                  onChange={(e) => setForm({ ...form, model_pattern: e.target.value })} />
                <p className="text-xs text-muted-foreground">{t('VoipTemplatesPage.form.modelPatternHelp')}</p>
              </div>
              <div className="grid gap-2">
                <Label>{t('VoipTemplatesPage.form.descriptionLabel')}</Label>
                <Input placeholder={t('VoipTemplatesPage.form.descriptionPlaceholder')} value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })} />
              </div>
            </div>

            {/* SIP Settings */}
            <div className="grid gap-2">
              <div className="flex items-center justify-between">
                <Label>{t('VoipTemplatesPage.form.sipSettingsLabel')}</Label>
                {!sipValid && <Badge variant="destructive" className="text-xs">{t('VoipTemplatesPage.form.invalidJson')}</Badge>}
              </div>
              <Textarea
                rows={6}
                className="font-mono text-xs"
                placeholder='{"sip_server": "pbx.example.com", "sip_port": 5060, "transport": "udp"}'
                value={form.sip_settings}
                onChange={(e) => setForm({ ...form, sip_settings: e.target.value })}
              />
            </div>

            {/* Network Settings */}
            <div className="grid gap-2">
              <div className="flex items-center justify-between">
                <Label>{t('VoipTemplatesPage.form.networkSettingsLabel')}</Label>
                {!netValid && <Badge variant="destructive" className="text-xs">{t('VoipTemplatesPage.form.invalidJson')}</Badge>}
              </div>
              <Textarea
                rows={4}
                className="font-mono text-xs"
                placeholder='{"vlan_id": 100, "dhcp": true, "ntp_server": "pool.ntp.org"}'
                value={form.network_settings}
                onChange={(e) => setForm({ ...form, network_settings: e.target.value })}
              />
            </div>

          </div>

          <DialogFooter>
            <Button variant="outline" onClick={closeDialog}>{t('VoipTemplatesPage.actions.cancel')}</Button>
            <Button onClick={handleSave} disabled={!formValid || createMutation.isPending || updateMutation.isPending}>
              {editingId ? (
                <><Pencil className="h-4 w-4 mr-2" /> {t('VoipTemplatesPage.actions.update')}</>
              ) : (
                <><Plus className="h-4 w-4 mr-2" /> {t('VoipTemplatesPage.actions.create')}</>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
