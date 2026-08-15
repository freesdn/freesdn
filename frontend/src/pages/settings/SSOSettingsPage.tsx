// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * SSO Admin Settings Page · CRUD management for SSO/OIDC/SAML/LDAP identity providers.
 */

import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ssoApi, type SSOProvider } from '@/lib/ssoApi';
import { getApiErrorMessage } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';
import { PageHeader } from '@/components/layout';
import { CapabilityMaturityBadge } from '@/components/ui/capability-maturity-badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Card, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState } from '@/components/ui/empty-state';
import { StatusBadge } from '@/components/ui/status-indicator';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Shield,
  Plus,
  Pencil,
  Trash2,
  CheckCircle,
  XCircle,
  Loader2,
  ArrowLeft,
  FlaskConical,
  RefreshCw,
} from 'lucide-react';
import { cn } from '@/lib/utils';

type PageView = 'list' | 'create' | 'edit';

interface FormData {
  name: string;
  slug: string;
  protocol: 'oidc' | 'saml' | 'ldap';
  is_enabled: boolean;
  // OIDC
  client_id: string;
  client_secret: string;
  issuer_url: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  scopes: string;
  // SAML
  entity_id: string;
  sso_url: string;
  slo_url: string;
  certificate: string;
  // LDAP
  ldap_url: string;
  ldap_base_dn: string;
  ldap_bind_dn: string;
  ldap_bind_password: string;
  ldap_user_filter: string;
  ldap_use_ssl: boolean;
  // Behavior
  auto_create_users: boolean;
  default_role: string;
}

const emptyForm: FormData = {
  name: '',
  slug: '',
  protocol: 'oidc',
  is_enabled: true,
  client_id: '',
  client_secret: '',
  issuer_url: '',
  authorization_endpoint: '',
  token_endpoint: '',
  userinfo_endpoint: '',
  scopes: 'openid profile email',
  entity_id: '',
  sso_url: '',
  slo_url: '',
  certificate: '',
  ldap_url: '',
  ldap_base_dn: '',
  ldap_bind_dn: '',
  ldap_bind_password: '',
  ldap_user_filter: '(uid={{username}})',
  ldap_use_ssl: true,
  auto_create_users: true,
  default_role: 'viewer',
};

const protocolLabels: Record<string, string> = {
  oidc: 'OpenID Connect',
  saml: 'SAML 2.0',
  ldap: 'LDAP / Active Directory',
};

const statusBadge = (enabled: boolean, t: (key: string) => string) =>
  enabled ? (
    <StatusBadge variant="success" hideIcon size="sm">
      <CheckCircle className="h-3 w-3 mr-1" /> {t('SSOSettingsPage.status.active')}
    </StatusBadge>
  ) : (
    <StatusBadge variant="neutral" hideIcon size="sm">
      <XCircle className="h-3 w-3 mr-1" /> {t('SSOSettingsPage.status.disabled')}
    </StatusBadge>
  );

export default function SSOSettingsPage({ embedded }: { embedded?: boolean } = {}) {
  const { t } = useTranslation('settings');
  const navigate = useNavigate();
  const { user } = useAuthStore();
  const [view, setView] = useState<PageView>('list');
  const [providers, setProviders] = useState<SSOProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; ok: boolean; msg: string } | null>(null);
  const [error, setError] = useState('');
  const [editId, setEditId] = useState<string | null>(null);
  const [form, setForm] = useState<FormData>(emptyForm);

  const loadProviders = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await ssoApi.listProviders();
      setProviders(data);
    } catch {
      setError(t('SSOSettingsPage.errors.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    loadProviders();
  }, [loadProviders]);

  const setField = <K extends keyof FormData>(key: K, val: FormData[K]) =>
    setForm((f) => ({ ...f, [key]: val }));

  const openCreate = () => {
    setForm(emptyForm);
    setEditId(null);
    setView('create');
  };

  const openEdit = (p: SSOProvider) => {
    setForm({
      name: p.name,
      slug: p.slug,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      protocol: p.protocol as any,
      is_enabled: p.status === 'active',
      client_id: p.oidc_client_id || '',
      client_secret: '', // Never echoed from server
      issuer_url: p.oidc_issuer || '',
      authorization_endpoint: '',
      token_endpoint: '',
      userinfo_endpoint: '',
      scopes: p.oidc_scopes || '',
      entity_id: p.saml_entity_id || '',
      sso_url: p.saml_sso_url || '',
      slo_url: p.saml_slo_url || '',
      certificate: '', // Sensitive, not returned from API
      ldap_url: p.ldap_url || '',
      ldap_base_dn: p.ldap_base_dn || '',
      ldap_bind_dn: p.ldap_bind_dn || '',
      ldap_bind_password: '', // Never echoed
      ldap_user_filter: p.ldap_user_search_filter || '(uid={{username}})',
      ldap_use_ssl: p.ldap_use_tls ?? true,
      auto_create_users: p.jit_provisioning ?? true,
      default_role: p.default_role || 'viewer',
    });
    setEditId(p.id);
    setView('edit');
  };

  const handleSave = async () => {
    setSaving(true);
    setError('');
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const payload: any = {
        name: form.name,
        slug: form.slug,
        protocol: form.protocol,
        status: form.is_enabled ? 'active' : 'inactive',
        jit_provisioning: form.auto_create_users,
        default_role: form.default_role,
      };

      // SSOProviderCreate requires organization_id; the create endpoint scopes
      // it to the current user's org. Include it so 'Add Provider' doesn't 422.
      if (!editId && user?.organization_id) {
        payload.organization_id = user.organization_id;
      }

      if (form.protocol === 'oidc') {
        payload.oidc_client_id = form.client_id;
        if (form.client_secret) payload.oidc_client_secret = form.client_secret;
        payload.oidc_issuer = form.issuer_url;
        payload.oidc_scopes = form.scopes || undefined;
      } else if (form.protocol === 'saml') {
        payload.saml_entity_id = form.entity_id;
        payload.saml_sso_url = form.sso_url;
        payload.saml_slo_url = form.slo_url || undefined;
        if (form.certificate) payload.saml_certificate = form.certificate;
      } else if (form.protocol === 'ldap') {
        payload.ldap_url = form.ldap_url;
        payload.ldap_base_dn = form.ldap_base_dn;
        payload.ldap_bind_dn = form.ldap_bind_dn;
        if (form.ldap_bind_password) payload.ldap_bind_password = form.ldap_bind_password;
        payload.ldap_user_search_filter = form.ldap_user_filter;
        payload.ldap_use_tls = form.ldap_use_ssl;
      }

      if (editId) {
        await ssoApi.updateProvider(editId, payload);
      } else {
        await ssoApi.createProvider(payload);
      }

      setView('list');
      await loadProviders();
    } catch (e: unknown) {
      setError(getApiErrorMessage(e, t('SSOSettingsPage.errors.saveFailed')));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm(t('SSOSettingsPage.confirmDelete'))) return;
    try {
      await ssoApi.deleteProvider(id);
      await loadProviders();
    } catch (e: unknown) {
      setError(getApiErrorMessage(e, t('SSOSettingsPage.errors.deleteFailed')));
    }
  };

  const handleTest = async (id: string) => {
    setTesting(id);
    setTestResult(null);
    try {
      const { data } = await ssoApi.testProvider(id);
      setTestResult({ id, ok: data.success, msg: data.message || (data.success ? t('SSOSettingsPage.test.ok') : t('SSOSettingsPage.test.failed')) });
    } catch (e: unknown) {
      setTestResult({ id, ok: false, msg: getApiErrorMessage(e, t('SSOSettingsPage.test.connectionFailed')) });
    } finally {
      setTesting(null);
    }
  };

  // ------------------------------------------------------------------
  // Provider list view
  // ------------------------------------------------------------------
  if (view === 'list') {
    return (
      <div className="space-y-6">
        {!embedded && (
          <>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => navigate('/settings/security')}
              className="gap-1"
            >
              <ArrowLeft className="h-4 w-4" />
              {t('SSOSettingsPage.backToSecurity')}
            </Button>

            <PageHeader
              icon={Shield}
              title={t('SSOSettingsPage.header.title')}
              subtitle={t('SSOSettingsPage.header.subtitle')}
              titleBadge={<CapabilityMaturityBadge capabilityId="sso" />}
              onRefresh={loadProviders}
              refreshing={loading}
              primaryAction={{
                label: t('SSOSettingsPage.actions.addProvider'),
                icon: Plus,
                onClick: openCreate,
              }}
            />
          </>
        )}
        {embedded && (
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold">{t('SSOSettingsPage.header.title')}</h3>
              <p className="text-sm text-muted-foreground">{t('SSOSettingsPage.header.subtitle')}</p>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={loadProviders} disabled={loading}>
                <RefreshCw className={cn('h-4 w-4 mr-1', loading && 'animate-spin')} />
                {t('SSOSettingsPage.actions.refresh')}
              </Button>
              <Button size="sm" onClick={openCreate}>
                <Plus className="h-4 w-4 mr-1" />
                {t('SSOSettingsPage.actions.addProvider')}
              </Button>
            </div>
          </div>
        )}

        {error && (
          <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
            {error}
          </div>
        )}

        {loading ? (
          <div className="space-y-4">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-16 w-full" />
          </div>
        ) : providers.length === 0 ? (
          <EmptyState
            icon={Shield}
            title={t('SSOSettingsPage.empty.title')}
            description={t('SSOSettingsPage.empty.description')}
            action={{ label: t('SSOSettingsPage.empty.action'), onClick: openCreate, icon: Plus }}
            variant="card"
          />
        ) : (
          <Card>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-border">
                <thead className="bg-muted/50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase text-muted-foreground">
                      {t('SSOSettingsPage.columns.provider')}
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase text-muted-foreground">
                      {t('SSOSettingsPage.columns.protocol')}
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase text-muted-foreground">
                      {t('SSOSettingsPage.columns.status')}
                    </th>
                    <th className="px-4 py-3 text-right text-xs font-medium uppercase text-muted-foreground">
                      {t('SSOSettingsPage.columns.actions')}
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {providers.map((p) => (
                    <tr key={p.id}>
                      <td className="whitespace-nowrap px-4 py-3 text-sm font-medium text-foreground">
                        {p.name}
                        <span className="ml-2 text-xs text-muted-foreground">({p.slug})</span>
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-sm text-muted-foreground">
                        {protocolLabels[p.protocol] || p.protocol?.toUpperCase() || '—'}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-sm">
                        {statusBadge(p.status === 'active', t)}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-right text-sm">
                        <div className="inline-flex items-center gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleTest(p.id)}
                            disabled={testing === p.id}
                            title={t('SSOSettingsPage.actions.testConnection')}
                          >
                            {testing === p.id ? (
                              <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                              <FlaskConical className="h-4 w-4" />
                            )}
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => openEdit(p)}
                            title={t('SSOSettingsPage.actions.edit')}
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleDelete(p.id)}
                            title={t('SSOSettingsPage.actions.delete')}
                            className="text-destructive hover:text-destructive/80 hover:bg-destructive/10"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                        {testResult?.id === p.id && (
                          <div className={`mt-1 text-xs ${testResult.ok ? 'text-green-600' : 'text-destructive'}`}>
                            {testResult.msg}
                          </div>
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
      </div>
    );
  }

  // ------------------------------------------------------------------
  // Create / Edit form view
  // ------------------------------------------------------------------
  return (
    <div className="space-y-6">
      <Button
        variant="ghost"
        size="sm"
        onClick={() => setView('list')}
        className="gap-1"
      >
        <ArrowLeft className="h-4 w-4" />
        {t('SSOSettingsPage.backToProviders')}
      </Button>

      <h2 className="text-xl font-bold text-foreground">
        {editId ? t('SSOSettingsPage.form.editTitle') : t('SSOSettingsPage.form.addTitle')}
      </h2>

      {error && (
        <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
          {error}
        </div>
      )}

      <Card>
        <CardContent noOffset className="space-y-6 p-6">
        {/* Basic Info */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>{t('SSOSettingsPage.fields.providerName')}</Label>
              <Input
                value={form.name}
                onChange={(e) => {
                  setField('name', e.target.value);
                  if (!editId) {
                    setField('slug', e.target.value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, ''));
                  }
                }}
                placeholder={t('SSOSettingsPage.fields.providerNamePlaceholder')}
              />
            </div>
            <div className="space-y-2">
              <Label>{t('SSOSettingsPage.fields.slug')}</Label>
              <Input
                value={form.slug}
                onChange={(e) => setField('slug', e.target.value)}
                placeholder="company-azure-ad"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>{t('SSOSettingsPage.fields.protocol')}</Label>
              <Select
                value={form.protocol}
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                onValueChange={(v) => setField('protocol', v as any)}
                disabled={!!editId}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="oidc">OpenID Connect (OIDC)</SelectItem>
                  {/* SAML callback is not yet implemented (returns 501) - the XSW-safe
                      validator is still pending, so SAML is disabled to avoid offering a
                      login path that can't complete. OIDC + LDAP are fully working. */}
                  <SelectItem value="saml" disabled>SAML 2.0 (coming soon)</SelectItem>
                  <SelectItem value="ldap">LDAP / Active Directory</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-end gap-3 pb-1">
              <div className="flex items-center gap-2">
                <Switch
                  checked={form.is_enabled}
                  onCheckedChange={(v) => setField('is_enabled', v)}
                />
                <Label>{t('SSOSettingsPage.fields.enabled')}</Label>
              </div>
            </div>
          </div>

        {/* OIDC Fields */}
        {form.protocol === 'oidc' && (
          <fieldset className="space-y-4 border-t border-border pt-4">
            <legend className="text-sm font-semibold text-foreground">
              {t('SSOSettingsPage.oidc.legend')}
            </legend>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field label={t('SSOSettingsPage.oidc.clientId')} value={form.client_id} onChange={(v) => setField('client_id', v)} />
              <Field label={t('SSOSettingsPage.oidc.clientSecret')} value={form.client_secret} onChange={(v) => setField('client_secret', v)} type="password" placeholder={editId ? t('SSOSettingsPage.placeholders.unchanged') : ''} />
              <Field label={t('SSOSettingsPage.oidc.issuerUrl')} value={form.issuer_url} onChange={(v) => setField('issuer_url', v)} placeholder="https://accounts.google.com" />
              <Field label={t('SSOSettingsPage.oidc.scopes')} value={form.scopes} onChange={(v) => setField('scopes', v)} />
              <Field label={t('SSOSettingsPage.oidc.authorizationEndpoint')} value={form.authorization_endpoint} onChange={(v) => setField('authorization_endpoint', v)} placeholder={t('SSOSettingsPage.placeholders.autoDiscoveredFromIssuer')} />
              <Field label={t('SSOSettingsPage.oidc.tokenEndpoint')} value={form.token_endpoint} onChange={(v) => setField('token_endpoint', v)} placeholder={t('SSOSettingsPage.placeholders.autoDiscovered')} />
              <Field label={t('SSOSettingsPage.oidc.userinfoEndpoint')} value={form.userinfo_endpoint} onChange={(v) => setField('userinfo_endpoint', v)} placeholder={t('SSOSettingsPage.placeholders.autoDiscovered')} />
            </div>
          </fieldset>
        )}

        {/* SAML Fields */}
        {form.protocol === 'saml' && (
          <fieldset className="space-y-4 border-t border-border pt-4">
            <legend className="text-sm font-semibold text-foreground">
              {t('SSOSettingsPage.saml.legend')}
            </legend>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field label={t('SSOSettingsPage.saml.entityId')} value={form.entity_id} onChange={(v) => setField('entity_id', v)} />
              <Field label={t('SSOSettingsPage.saml.ssoUrl')} value={form.sso_url} onChange={(v) => setField('sso_url', v)} />
              <Field label={t('SSOSettingsPage.saml.sloUrl')} value={form.slo_url} onChange={(v) => setField('slo_url', v)} />
            </div>
            <div className="space-y-2">
              <Label>{t('SSOSettingsPage.saml.certificate')}</Label>
              <Textarea
                value={form.certificate}
                onChange={(e) => setField('certificate', e.target.value)}
                rows={5}
                className="font-mono text-xs"
                placeholder="-----BEGIN CERTIFICATE-----"
              />
            </div>
          </fieldset>
        )}

        {/* LDAP Fields */}
        {form.protocol === 'ldap' && (
          <fieldset className="space-y-4 border-t border-border pt-4">
            <legend className="text-sm font-semibold text-foreground">
              {t('SSOSettingsPage.ldap.legend')}
            </legend>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field label={t('SSOSettingsPage.ldap.url')} value={form.ldap_url} onChange={(v) => setField('ldap_url', v)} placeholder="ldaps://ldap.example.com:636" />
              <Field label={t('SSOSettingsPage.ldap.baseDn')} value={form.ldap_base_dn} onChange={(v) => setField('ldap_base_dn', v)} placeholder="dc=example,dc=com" />
              <Field label={t('SSOSettingsPage.ldap.bindDn')} value={form.ldap_bind_dn} onChange={(v) => setField('ldap_bind_dn', v)} placeholder="cn=admin,dc=example,dc=com" />
              <Field label={t('SSOSettingsPage.ldap.bindPassword')} value={form.ldap_bind_password} onChange={(v) => setField('ldap_bind_password', v)} type="password" placeholder={editId ? t('SSOSettingsPage.placeholders.unchanged') : ''} />
              <Field label={t('SSOSettingsPage.ldap.userFilter')} value={form.ldap_user_filter} onChange={(v) => setField('ldap_user_filter', v)} />
            </div>
            <div className="flex items-center gap-2">
              <Switch
                checked={form.ldap_use_ssl}
                onCheckedChange={(v) => setField('ldap_use_ssl', v)}
              />
              <Label>{t('SSOSettingsPage.ldap.useSsl')}</Label>
            </div>
          </fieldset>
        )}

        {/* Provisioning */}
        <fieldset className="space-y-4 border-t border-border pt-4">
          <legend className="text-sm font-semibold text-foreground">
            {t('SSOSettingsPage.provisioning.legend')}
          </legend>
          <div className="flex items-center gap-2">
            <Switch
              checked={form.auto_create_users}
              onCheckedChange={(v) => setField('auto_create_users', v)}
            />
            <Label>
              {t('SSOSettingsPage.provisioning.autoCreate')}
            </Label>
          </div>
          <div className="max-w-xs space-y-2">
            <Label>{t('SSOSettingsPage.provisioning.defaultRole')}</Label>
            <Select
              value={form.default_role}
              onValueChange={(v) => setField('default_role', v)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="viewer">{t('SSOSettingsPage.roles.viewer')}</SelectItem>
                <SelectItem value="operator">{t('SSOSettingsPage.roles.operator')}</SelectItem>
                <SelectItem value="org_admin">{t('SSOSettingsPage.roles.admin')}</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </fieldset>

        {/* Actions */}
        <div className="flex justify-end gap-3 border-t border-border pt-4">
          <Button variant="outline" onClick={() => setView('list')}>
            {t('SSOSettingsPage.actions.cancel')}
          </Button>
          <Button
            onClick={handleSave}
            disabled={saving || !form.name || !form.slug}
          >
            {saving && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            {editId ? t('SSOSettingsPage.actions.updateProvider') : t('SSOSettingsPage.actions.createProvider')}
          </Button>
        </div>
        </CardContent>
      </Card>
    </div>
  );
}

// Simple reusable text field
function Field({
  label,
  value,
  onChange,
  type = 'text',
  placeholder = '',
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
  placeholder?: string;
}) {
  return (
    <div className="space-y-2">
      <Label>{label}</Label>
      <Input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
      />
    </div>
  );
}
