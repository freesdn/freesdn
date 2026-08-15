// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Firewall Management Page (Enterprise)
 *
 * Unified firewall management with URL-based tab routing.
 * Supports deep integration with OPNsense, pfSense, and MikroTik.
 *
 * Tabs:
 *   /firewall               → Dashboard
 *   /firewall/gateways      → Gateway integrations (CRUD)
 *   /firewall/rules         → Firewall rules (local DB)
 *   /firewall/nat-rules     → NAT translation rules
 *   /firewall/vpn           → VPN tunnels
 *   /firewall/ids           → IDS/IPS alerts
 *   /firewall/logs          → Firewall traffic logs
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useLocation, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import {
  Shield,
  ShieldAlert,
  Network,
  Globe,
  Lock,
  AlertTriangle,
  Settings,
  MoreHorizontal,
  CheckCircle,
  XCircle,
  AlertCircle,
  Activity,
  RefreshCw,
  Plus,
  ArrowRight,
  Trash2,
  Edit,
  Eye,
  EyeOff,
  Server,
  Wifi,
  WifiOff,
  Ban,
  BarChart3,
  FileText,
  Zap,
  GitMerge,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { cn } from '@/lib/utils';
import { EmptyState } from '@/components/ui/empty-state';
import { StatsGrid } from '@/components/ui/stats-grid';
import { useToast } from '@/hooks/use-toast';
import { PageHeader } from '@/components/layout';
import {
  firewallApi,
  gatewayApi,
  sitesApiV2,
  type GatewayConnection,
  type GatewayConnectionCreate,
  type GatewayTestRequest,
  type GatewayTestResponse,
  type GatewaySummary,
  type Site,
} from '@/lib/api';

// =============================================================================
// Types
// =============================================================================

interface FirewallRule {
  id: string;
  device_id?: string;
  name: string;
  rule_order: number;
  source_address: string;
  source_port?: string;
  dest_address: string;
  dest_port?: string;
  source_zone?: string;
  dest_zone?: string;
  protocol: string;
  action: 'allow' | 'deny' | 'reject' | 'log';
  is_enabled: boolean;
  hit_count: number;
  log_enabled?: boolean;
  description?: string;
  created_at?: string;
  updated_at?: string;
}

interface NATRule {
  id: string;
  device_id?: string;
  name: string;
  nat_type: 'snat' | 'dnat' | 'masquerade' | 'redirect';
  original_address: string;
  original_port?: string;
  translated_address: string;
  translated_port?: string;
  protocol: string;
  interface?: string;
  is_enabled: boolean;
  description?: string;
  created_at?: string;
}

interface VPNTunnel {
  id: string;
  device_id?: string;
  name: string;
  vpn_type: 'ipsec' | 'openvpn' | 'wireguard' | 'l2tp';
  status: 'up' | 'down' | 'connecting' | 'error';
  local_address?: string;
  local_subnets?: any;
  remote_address?: string;
  remote_subnets?: any;
  auth_type?: string;
  bytes_in?: number;
  bytes_out?: number;
  last_connected?: string;
  is_enabled?: boolean;
  description?: string;
  created_at?: string;
}

interface IDSAlert {
  id: string;
  device_id?: string;
  signature_id?: string;
  signature_name: string;
  category?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source_ip: string;
  dest_ip: string;
  source_port?: number;
  dest_port?: number;
  protocol?: string;
  action_taken?: string;
  timestamp: string;
  is_acknowledged: boolean;
  acknowledged_by?: string;
  acknowledged_at?: string;
}

interface FirewallLog {
  id: string;
  device_id?: string;
  rule_id?: string;
  timestamp: string;
  source_ip: string;
  source_port?: number;
  dest_ip: string;
  dest_port?: number;
  source_zone?: string;
  dest_zone?: string;
  protocol: string;
  action: string;
  bytes_sent?: number;
  bytes_received?: number;
  application?: string;
}

// =============================================================================
// Badge Components
// =============================================================================

function ActionBadge({ action }: { action: string }) {
  const { t } = useTranslation('firewall');
  const config: Record<string, { icon: typeof CheckCircle; label: string; className: string }> = {
    allow: { icon: CheckCircle, label: t('FirewallPage.action.allow'), className: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' },
    pass: { icon: CheckCircle, label: t('FirewallPage.action.pass'), className: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' },
    deny: { icon: XCircle, label: t('FirewallPage.action.deny'), className: 'bg-red-500/10 text-red-500 border-red-500/20' },
    block: { icon: XCircle, label: t('FirewallPage.action.block'), className: 'bg-red-500/10 text-red-500 border-red-500/20' },
    reject: { icon: Ban, label: t('FirewallPage.action.reject'), className: 'bg-amber-500/10 text-amber-500 border-amber-500/20' },
    log: { icon: Eye, label: t('FirewallPage.action.log'), className: 'bg-blue-500/10 text-blue-500 border-blue-500/20' },
  };
  const { icon: Icon, label, className } = config[action] || config.deny;
  return (
    <Badge variant="outline" className={cn('gap-1', className)}>
      <Icon className="h-3 w-3" />
      {label}
    </Badge>
  );
}

function VPNStatusBadge({ status }: { status: string }) {
  const { t } = useTranslation('firewall');
  const config: Record<string, { icon: typeof CheckCircle; label: string; className: string }> = {
    up: { icon: CheckCircle, label: t('FirewallPage.vpnStatus.up'), className: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' },
    down: { icon: XCircle, label: t('FirewallPage.vpnStatus.down'), className: 'bg-red-500/10 text-red-500 border-red-500/20' },
    connecting: { icon: Activity, label: t('FirewallPage.vpnStatus.connecting'), className: 'bg-blue-500/10 text-blue-500 border-blue-500/20 animate-pulse' },
    error: { icon: AlertCircle, label: t('FirewallPage.vpnStatus.error'), className: 'bg-amber-500/10 text-amber-500 border-amber-500/20' },
  };
  const { icon: Icon, label, className } = config[status] || config.down;
  return (
    <Badge variant="outline" className={cn('gap-1', className)}>
      <Icon className="h-3 w-3" />
      {label}
    </Badge>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const { t } = useTranslation('firewall');
  const config: Record<string, { label: string; className: string }> = {
    critical: { label: t('FirewallPage.severity.critical'), className: 'bg-red-500 text-white' },
    high: { label: t('FirewallPage.severity.high'), className: 'bg-orange-500 text-white' },
    medium: { label: t('FirewallPage.severity.medium'), className: 'bg-amber-500 text-white' },
    low: { label: t('FirewallPage.severity.low'), className: 'bg-blue-500 text-white' },
    info: { label: t('FirewallPage.severity.info'), className: 'bg-gray-500 text-white' },
  };
  const { label, className } = config[severity] || config.info;
  return <Badge className={className}>{label}</Badge>;
}

function VendorBadge({ vendor }: { vendor: string }) {
  const config: Record<string, { label: string; className: string }> = {
    opnsense: { label: 'OPNsense', className: 'bg-orange-500/10 text-orange-600 border-orange-500/20' },
    pfsense: { label: 'pfSense', className: 'bg-blue-500/10 text-blue-600 border-blue-500/20' },
    mikrotik: { label: 'MikroTik', className: 'bg-sky-500/10 text-sky-600 border-sky-500/20' },
    openwrt: { label: 'OpenWRT', className: 'bg-green-500/10 text-green-600 border-green-500/20' },
  };
  const { label, className } = config[vendor] || { label: vendor, className: 'bg-muted text-muted-foreground' };
  return <Badge variant="outline" className={cn('font-medium', className)}>{label}</Badge>;
}

function SyncStatusBadge({ status }: { status: string }) {
  const { t } = useTranslation('firewall');
  const config: Record<string, { label: string; className: string }> = {
    success: { label: t('FirewallPage.syncStatus.success'), className: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' },
    failed: { label: t('FirewallPage.syncStatus.failed'), className: 'bg-red-500/10 text-red-500 border-red-500/20' },
    syncing: { label: t('FirewallPage.syncStatus.syncing'), className: 'bg-blue-500/10 text-blue-500 border-blue-500/20 animate-pulse' },
    never: { label: t('FirewallPage.syncStatus.never'), className: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20' },
    idle: { label: t('FirewallPage.syncStatus.idle'), className: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20' },
  };
  const { label, className } = config[status] || { label: status, className: '' };
  return <Badge variant="outline" className={className}>{label}</Badge>;
}

// =============================================================================
// Add Gateway Dialog
// =============================================================================

interface AddGatewayDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (data: GatewayConnectionCreate) => void;
  onTestConnection: (data: GatewayTestRequest) => Promise<any>;
  isSubmitting: boolean;
  testResult: GatewayTestResponse | null;
  isTesting: boolean;
  sites: Site[];
}

function AddGatewayDialog({
  open,
  onOpenChange,
  onSubmit,
  onTestConnection,
  isSubmitting,
  testResult,
  isTesting,
  sites,
}: AddGatewayDialogProps) {
  const { t } = useTranslation('firewall');
  const initialForm = {
    name: '',
    vendor: '' as '' | 'opnsense' | 'pfsense' | 'mikrotik' | 'openwrt',
    host: '',
    port: '443',
    verify_ssl: false,
    api_key: '',
    api_secret: '',
    username: '',
    password: '',
    description: '',
    sync_enabled: true,
    sync_interval_seconds: '300',
    site_id: '',
  };

  const [form, setForm] = useState(initialForm);
  const [showSecret, setShowSecret] = useState(false);

  // Clear form + credentials when dialog closes
  const handleDialogOpenChange = (v: boolean) => {
    onOpenChange(v);
    if (!v) { setForm(initialForm); setShowSecret(false); }
  };

  const updateField = (field: string, value: string | boolean) =>
    setForm((prev) => ({ ...prev, [field]: value }));

  const handleTest = () => {
    onTestConnection({
      vendor: form.vendor as 'opnsense' | 'pfsense' | 'mikrotik' | 'openwrt',
      host: form.host,
      port: parseInt(form.port, 10) || 443,
      verify_ssl: form.verify_ssl,
      api_key: form.api_key || undefined,
      api_secret: form.api_secret || undefined,
      username: form.username || undefined,
      password: form.password || undefined,
    });
  };

  const handleSubmit = () => {
    onSubmit({
      name: form.name,
      vendor: form.vendor,
      host: form.host,
      port: parseInt(form.port, 10) || 443,
      verify_ssl: form.verify_ssl,
      api_key: form.api_key || undefined,
      api_secret: form.api_secret || undefined,
      username: form.username || undefined,
      password: form.password || undefined,
      description: form.description || undefined,
      sync_enabled: form.sync_enabled,
      sync_interval_seconds: parseInt(form.sync_interval_seconds, 10) || 300,
      site_id: form.site_id || undefined,
    } as any);
  };

  const usesBasicAuth = form.vendor === 'mikrotik' || form.vendor === 'openwrt';
  const isValidHost = /^[a-zA-Z0-9._-]+$/.test(form.host.trim());
  const portNum = parseInt(form.port, 10);
  const isValidPort = !form.port || (portNum >= 1 && portNum <= 65535);
  const canTest = form.vendor && form.host.trim() && isValidHost && isValidPort;
  const canSubmit = form.name.trim() && form.vendor && form.host.trim() && isValidHost && isValidPort;

  return (
    <Dialog open={open} onOpenChange={handleDialogOpenChange}>
      <DialogContent className="sm:max-w-[580px] max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            {t('FirewallPage.addDialog.title')}
          </DialogTitle>
          <DialogDescription>
            {t('FirewallPage.addDialog.description')}
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 py-2">
          {/* Name */}
          <div className="grid gap-2">
            <Label htmlFor="gw_name">{t('FirewallPage.fields.name')}</Label>
            <Input
              id="gw_name"
              placeholder={t('FirewallPage.fields.namePlaceholder')}
              value={form.name}
              onChange={(e) => updateField('name', e.target.value)}
            />
          </div>

          {/* Vendor */}
          <div className="grid gap-2">
            <Label>{t('FirewallPage.fields.firewallSoftware')}</Label>
            <Select value={form.vendor} onValueChange={(v) => updateField('vendor', v)}>
              <SelectTrigger>
                <SelectValue placeholder={t('FirewallPage.fields.selectFirewallType')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="opnsense">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-orange-500" />
                    OPNsense
                  </div>
                </SelectItem>
                <SelectItem value="pfsense">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-blue-500" />
                    pfSense
                  </div>
                </SelectItem>
                <SelectItem value="mikrotik">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-sky-500" />
                    MikroTik RouterOS
                  </div>
                </SelectItem>
                <SelectItem value="openwrt">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-green-500" />
                    OpenWRT
                  </div>
                </SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Connection */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
            <div className="col-span-2 grid gap-2">
              <Label htmlFor="gw_host">{t('FirewallPage.fields.hostIp')}</Label>
              <Input
                id="gw_host"
                placeholder={t('FirewallPage.fields.hostPlaceholder')}
                value={form.host}
                onChange={(e) => updateField('host', e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="gw_port">{t('FirewallPage.fields.port')}</Label>
              <Input
                id="gw_port"
                placeholder={form.vendor === 'mikrotik' ? '8728' : '443'}
                value={form.port}
                onChange={(e) => updateField('port', e.target.value)}
              />
            </div>
          </div>

          {/* Credentials · OPNsense / pfSense (API Key) */}
          {!usesBasicAuth && form.vendor && (
            <>
              <div className="grid gap-2">
                <Label htmlFor="gw_api_key">{t('FirewallPage.fields.apiKey')}</Label>
                <Input
                  id="gw_api_key"
                  placeholder={t('FirewallPage.fields.apiKeyPlaceholder')}
                  value={form.api_key}
                  onChange={(e) => updateField('api_key', e.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="gw_api_secret">{t('FirewallPage.fields.apiSecret')}</Label>
                <div className="relative">
                  <Input
                    id="gw_api_secret"
                    type={showSecret ? 'text' : 'password'}
                    placeholder={t('FirewallPage.fields.apiSecretPlaceholder')}
                    value={form.api_secret}
                    onChange={(e) => updateField('api_secret', e.target.value)}
                    className="pr-10"
                  />
                  <Button type="button" variant="ghost" size="icon" className="absolute right-0 top-0 h-full px-3" onClick={() => setShowSecret(!showSecret)}>
                    {showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                </div>
              </div>
            </>
          )}

          {/* Credentials · MikroTik / OpenWRT (Basic Auth) */}
          {usesBasicAuth && (
            <>
              <div className="grid gap-2">
                <Label htmlFor="gw_username">{t('FirewallPage.fields.username')}</Label>
                <Input
                  id="gw_username"
                  placeholder={t('FirewallPage.fields.usernamePlaceholder')}
                  value={form.username}
                  onChange={(e) => updateField('username', e.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="gw_password">{t('FirewallPage.fields.password')}</Label>
                <div className="relative">
                  <Input
                    id="gw_password"
                    type={showSecret ? 'text' : 'password'}
                    placeholder={t('FirewallPage.fields.passwordPlaceholder')}
                    value={form.password}
                    onChange={(e) => updateField('password', e.target.value)}
                    className="pr-10"
                  />
                  <Button type="button" variant="ghost" size="icon" className="absolute right-0 top-0 h-full px-3" onClick={() => setShowSecret(!showSecret)}>
                    {showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                </div>
              </div>
            </>
          )}

          {/* Description */}
          <div className="grid gap-2">
            <Label htmlFor="gw_desc">{t('FirewallPage.fields.descriptionOptional')}</Label>
            <Input
              id="gw_desc"
              placeholder={t('FirewallPage.fields.descriptionPlaceholder')}
              value={form.description}
              onChange={(e) => updateField('description', e.target.value)}
            />
          </div>

          {/* Site assignment */}
          {sites.length > 0 && (
            <div className="grid gap-2">
              <Label>{t('FirewallPage.fields.siteLocationOptional')}</Label>
              <Select value={form.site_id} onValueChange={(v) => updateField('site_id', v === '__none__' ? '' : v)}>
                <SelectTrigger>
                  <SelectValue placeholder={t('FirewallPage.fields.assignToSite')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__none__">{t('FirewallPage.fields.noSite')}</SelectItem>
                  {sites.map((s) => (
                    <SelectItem key={s.id} value={s.id}>{s.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {t('FirewallPage.fields.siteBindHint')}
              </p>
            </div>
          )}

          {/* Test connection result */}
          {testResult && (
            <Card className={cn(testResult.success ? 'border-emerald-500/50' : 'border-red-500/50')}>
              <CardContent noOffset className="py-3">
                <div className="flex items-center gap-2">
                  {testResult.success ? (
                    <CheckCircle className="h-5 w-5 text-emerald-500" />
                  ) : (
                    <XCircle className="h-5 w-5 text-red-500" />
                  )}
                  <div>
                    <p className="text-sm font-medium">{testResult.message}</p>
                    {testResult.hostname && (
                      <p className="text-xs text-muted-foreground">
                        {testResult.hostname} · {testResult.version} ({testResult.model})
                        {testResult.latency_ms && ` · ${testResult.latency_ms}ms`}
                      </p>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={handleTest} disabled={!canTest || isTesting}>
            {isTesting ? (
              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Zap className="h-4 w-4 mr-2" />
            )}
            {t('FirewallPage.actions.testConnection')}
          </Button>
          <Button onClick={handleSubmit} disabled={!canSubmit || isSubmitting}>
            {isSubmitting ? (
              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Plus className="h-4 w-4 mr-2" />
            )}
            {t('FirewallPage.actions.addGateway')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// =============================================================================
// Edit Gateway Dialog
// =============================================================================

interface EditGatewayDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  gateway: GatewayConnection;
  onSubmit: (id: string, data: import('@/lib/api').GatewayConnectionUpdate) => void;
  onTestConnection: (id: string, overrides?: { verify_ssl?: boolean; host?: string; port?: number }) => Promise<any>;
  isSubmitting: boolean;
  testResult: GatewayTestResponse | null;
  isTesting: boolean;
  sites: Site[];
}

function EditGatewayDialog({
  open,
  onOpenChange,
  gateway,
  onSubmit,
  onTestConnection,
  isSubmitting,
  testResult,
  isTesting,
  sites,
}: EditGatewayDialogProps) {
  const { t } = useTranslation('firewall');
  const [form, setForm] = useState({
    name: gateway.name,
    host: gateway.host,
    port: String(gateway.port),
    verify_ssl: gateway.verify_ssl,
    api_key: '',
    api_secret: '',
    username: '',
    password: '',
    description: gateway.description || '',
    sync_enabled: gateway.sync_enabled,
    sync_interval_seconds: String(gateway.sync_interval_seconds),
    site_id: gateway.site_id || '',
  });

  // Reset form when gateway changes
  const gwId = gateway.id;
  const [lastGwId, setLastGwId] = useState(gwId);
  if (gwId !== lastGwId) {
    setLastGwId(gwId);
    setForm({
      name: gateway.name,
      host: gateway.host,
      port: String(gateway.port),
      verify_ssl: gateway.verify_ssl,
      api_key: '',
      api_secret: '',
      username: '',
      password: '',
      description: gateway.description || '',
      sync_enabled: gateway.sync_enabled,
      sync_interval_seconds: String(gateway.sync_interval_seconds),
      site_id: gateway.site_id || '',
    });
  }

  const [showSecret, setShowSecret] = useState(false);

  const updateField = (field: string, value: string | boolean) =>
    setForm((prev) => ({ ...prev, [field]: value }));

  const handleTest = () => {
    // Send the CURRENT form values so a toggled Verify SSL / changed host:port
    // is honored against the stored creds, without forcing a Save first.
    onTestConnection(gateway.id, {
      verify_ssl: form.verify_ssl,
      host: form.host || undefined,
      port: parseInt(form.port, 10) || undefined,
    });
  };

  const handleSubmit = () => {
    const data: Record<string, any> = {};
    if (form.name !== gateway.name) data.name = form.name;
    if (form.description !== (gateway.description || '')) data.description = form.description;
    if (form.host !== gateway.host) data.host = form.host;
    if (parseInt(form.port, 10) !== gateway.port) data.port = parseInt(form.port, 10);
    if (form.verify_ssl !== gateway.verify_ssl) data.verify_ssl = form.verify_ssl;
    if (form.sync_enabled !== gateway.sync_enabled) data.sync_enabled = form.sync_enabled;
    if (parseInt(form.sync_interval_seconds, 10) !== gateway.sync_interval_seconds)
      data.sync_interval_seconds = parseInt(form.sync_interval_seconds, 10);

    // Site assignment
    const newSiteId = form.site_id || null;
    const oldSiteId = gateway.site_id || null;
    if (newSiteId !== oldSiteId) data.site_id = newSiteId;

    // Only send credentials if user typed new ones
    if (gateway.vendor === 'mikrotik' || gateway.vendor === 'openwrt') {
      if (form.username) data.username = form.username;
      if (form.password) data.password = form.password;
    } else {
      if (form.api_key) data.api_key = form.api_key;
      if (form.api_secret) data.api_secret = form.api_secret;
    }

    onSubmit(gateway.id, data);
  };

  const usesBasicAuth = gateway.vendor === 'mikrotik' || gateway.vendor === 'openwrt';
  const canSubmit = form.name.trim() && form.host;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[580px] max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Edit className="h-5 w-5" />
            {t('FirewallPage.editDialog.title', { name: gateway.name })}
          </DialogTitle>
          <DialogDescription>
            {t('FirewallPage.editDialog.description')}
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 py-2">
          {/* Name */}
          <div className="grid gap-2">
            <Label htmlFor="edit_gw_name">{t('FirewallPage.fields.name')}</Label>
            <Input
              id="edit_gw_name"
              placeholder={t('FirewallPage.fields.namePlaceholder')}
              value={form.name}
              onChange={(e) => updateField('name', e.target.value)}
            />
          </div>

          {/* Vendor (read-only) */}
          <div className="grid gap-2">
            <Label>{t('FirewallPage.fields.firewallSoftware')}</Label>
            <div className="flex items-center gap-2 p-2 border rounded-md bg-muted/50">
              <VendorBadge vendor={gateway.vendor} />
              <span className="text-sm text-muted-foreground">{t('FirewallPage.fields.cannotBeChanged')}</span>
            </div>
          </div>

          {/* Connection */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
            <div className="col-span-2 grid gap-2">
              <Label htmlFor="edit_gw_host">{t('FirewallPage.fields.hostIp')}</Label>
              <Input
                id="edit_gw_host"
                placeholder={t('FirewallPage.fields.hostPlaceholder')}
                value={form.host}
                onChange={(e) => updateField('host', e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="edit_gw_port">{t('FirewallPage.fields.port')}</Label>
              <Input
                id="edit_gw_port"
                placeholder={gateway.vendor === 'mikrotik' ? '8728' : '443'}
                value={form.port}
                onChange={(e) => updateField('port', e.target.value)}
              />
            </div>
          </div>

          {/* SSL */}
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="edit_gw_ssl"
              checked={form.verify_ssl}
              onChange={(e) => updateField('verify_ssl', e.target.checked)}
              className="h-4 w-4 rounded border-input"
            />
            <Label htmlFor="edit_gw_ssl">{t('FirewallPage.fields.verifySsl')}</Label>
          </div>

          {/* Credentials · OPNsense / pfSense (API Key) */}
          {!usesBasicAuth && (
            <>
              <div className="grid gap-2">
                <Label htmlFor="edit_gw_api_key">{t('FirewallPage.fields.apiKey')}</Label>
                <Input
                  id="edit_gw_api_key"
                  placeholder={t('FirewallPage.fields.apiKeyKeepPlaceholder')}
                  value={form.api_key}
                  onChange={(e) => updateField('api_key', e.target.value)}
                />
                <p className="text-xs text-muted-foreground">{t('FirewallPage.fields.keepCurrentCredentials')}</p>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="edit_gw_api_secret">{t('FirewallPage.fields.apiSecret')}</Label>
                <div className="relative">
                  <Input
                    id="edit_gw_api_secret"
                    type={showSecret ? 'text' : 'password'}
                    placeholder={t('FirewallPage.fields.apiSecretKeepPlaceholder')}
                    value={form.api_secret}
                    onChange={(e) => updateField('api_secret', e.target.value)}
                    className="pr-10"
                  />
                  <Button type="button" variant="ghost" size="icon" className="absolute right-0 top-0 h-full px-3" onClick={() => setShowSecret(!showSecret)}>
                    {showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                </div>
              </div>
            </>
          )}

          {/* Credentials · MikroTik / OpenWRT (Basic Auth) */}
          {usesBasicAuth && (
            <>
              <div className="grid gap-2">
                <Label htmlFor="edit_gw_username">{t('FirewallPage.fields.username')}</Label>
                <Input
                  id="edit_gw_username"
                  placeholder={t('FirewallPage.fields.keepExistingPlaceholder')}
                  value={form.username}
                  onChange={(e) => updateField('username', e.target.value)}
                />
                <p className="text-xs text-muted-foreground">{t('FirewallPage.fields.keepCurrentCredentials')}</p>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="edit_gw_password">{t('FirewallPage.fields.password')}</Label>
                <div className="relative">
                  <Input
                    id="edit_gw_password"
                    type={showSecret ? 'text' : 'password'}
                    placeholder={t('FirewallPage.fields.keepExistingPlaceholder')}
                    value={form.password}
                    onChange={(e) => updateField('password', e.target.value)}
                    className="pr-10"
                  />
                  <Button type="button" variant="ghost" size="icon" className="absolute right-0 top-0 h-full px-3" onClick={() => setShowSecret(!showSecret)}>
                    {showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                </div>
              </div>
            </>
          )}

          {/* Description */}
          <div className="grid gap-2">
            <Label htmlFor="edit_gw_desc">{t('FirewallPage.fields.descriptionOptional')}</Label>
            <Input
              id="edit_gw_desc"
              placeholder={t('FirewallPage.fields.descriptionPlaceholder')}
              value={form.description}
              onChange={(e) => updateField('description', e.target.value)}
            />
          </div>

          {/* Site assignment */}
          {sites.length > 0 && (
            <div className="grid gap-2">
              <Label>{t('FirewallPage.fields.siteLocation')}</Label>
              <Select value={form.site_id || '__none__'} onValueChange={(v) => updateField('site_id', v === '__none__' ? '' : v)}>
                <SelectTrigger>
                  <SelectValue placeholder={t('FirewallPage.fields.assignToSite')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__none__">{t('FirewallPage.fields.noSite')}</SelectItem>
                  {sites.map((s) => (
                    <SelectItem key={s.id} value={s.id}>{s.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {t('FirewallPage.fields.siteBindHintOmada')}
              </p>
            </div>
          )}

          {/* Sync settings */}
          <div className="grid gap-4 pt-2 border-t">
            <h4 className="text-sm font-semibold">{t('FirewallPage.fields.syncConfiguration')}</h4>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="edit_gw_sync"
                checked={form.sync_enabled}
                onChange={(e) => updateField('sync_enabled', e.target.checked)}
                className="h-4 w-4 rounded border-input"
              />
              <Label htmlFor="edit_gw_sync">{t('FirewallPage.fields.enableAutoSync')}</Label>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="edit_gw_interval">{t('FirewallPage.fields.syncInterval')}</Label>
              <Input
                id="edit_gw_interval"
                type="number"
                min="30"
                max="86400"
                value={form.sync_interval_seconds}
                onChange={(e) => updateField('sync_interval_seconds', e.target.value)}
                disabled={!form.sync_enabled}
              />
            </div>
          </div>

          {/* Test connection result */}
          {testResult && (
            <Card className={cn(testResult.success ? 'border-emerald-500/50' : 'border-red-500/50')}>
              <CardContent noOffset className="py-3">
                <div className="flex items-center gap-2">
                  {testResult.success ? (
                    <CheckCircle className="h-5 w-5 text-emerald-500" />
                  ) : (
                    <XCircle className="h-5 w-5 text-red-500" />
                  )}
                  <div>
                    <p className="text-sm font-medium">{testResult.message}</p>
                    {testResult.hostname && (
                      <p className="text-xs text-muted-foreground">
                        {testResult.hostname} · {testResult.version} ({testResult.model})
                        {testResult.latency_ms && ` · ${testResult.latency_ms}ms`}
                      </p>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={handleTest} disabled={isTesting}>
            {isTesting ? (
              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Zap className="h-4 w-4 mr-2" />
            )}
            {t('FirewallPage.actions.testConnection')}
          </Button>
          <Button onClick={handleSubmit} disabled={!canSubmit || isSubmitting}>
            {isSubmitting ? (
              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Settings className="h-4 w-4 mr-2" />
            )}
            {t('FirewallPage.actions.saveChanges')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// =============================================================================
// Edit Rule Dialog
// =============================================================================

interface EditRuleDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  rule: FirewallRule;
  onSubmit: (id: string, data: Record<string, unknown>) => void;
  isSubmitting: boolean;
}

function EditRuleDialog({ open, onOpenChange, rule, onSubmit, isSubmitting }: EditRuleDialogProps) {
  const { t } = useTranslation('firewall');
  const buildForm = (r: FirewallRule) => ({
    name: r.name,
    source_address: r.source_address || '',
    source_port: r.source_port || '',
    dest_address: r.dest_address || '',
    dest_port: r.dest_port || '',
    protocol: r.protocol || 'any',
    action: r.action as string,
    is_enabled: r.is_enabled,
    description: r.description || '',
  });
  const [form, setForm] = useState(buildForm(rule));

  // Reset form when the rule changes
  const [lastRuleId, setLastRuleId] = useState(rule.id);
  if (rule.id !== lastRuleId) {
    setLastRuleId(rule.id);
    setForm(buildForm(rule));
  }

  const updateField = (field: string, value: string | boolean) =>
    setForm((prev) => ({ ...prev, [field]: value }));

  const handleSubmit = () => {
    onSubmit(rule.id, {
      name: form.name,
      source_address: form.source_address,
      source_port: form.source_port || null,
      dest_address: form.dest_address,
      dest_port: form.dest_port || null,
      protocol: form.protocol,
      action: form.action,
      is_enabled: form.is_enabled,
      description: form.description || null,
    });
  };

  const canSubmit = form.name.trim().length > 0;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[580px] max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Edit className="h-5 w-5" />
            {t('FirewallPage.actions.editRule')}
          </DialogTitle>
        </DialogHeader>

        <div className="grid gap-4 py-2">
          {/* Name */}
          <div className="grid gap-2">
            <Label htmlFor="edit_rule_name">{t('FirewallPage.ruleColumns.rule')}</Label>
            <Input
              id="edit_rule_name"
              value={form.name}
              onChange={(e) => updateField('name', e.target.value)}
            />
          </div>

          {/* Source */}
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-2">
              <Label htmlFor="edit_rule_src">{t('FirewallPage.ruleColumns.source')}</Label>
              <Input
                id="edit_rule_src"
                placeholder="any"
                value={form.source_address}
                onChange={(e) => updateField('source_address', e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="edit_rule_src_port">{t('FirewallPage.fields.port')}</Label>
              <Input
                id="edit_rule_src_port"
                value={form.source_port}
                onChange={(e) => updateField('source_port', e.target.value)}
              />
            </div>
          </div>

          {/* Destination */}
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-2">
              <Label htmlFor="edit_rule_dst">{t('FirewallPage.ruleColumns.destination')}</Label>
              <Input
                id="edit_rule_dst"
                placeholder="any"
                value={form.dest_address}
                onChange={(e) => updateField('dest_address', e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="edit_rule_dst_port">{t('FirewallPage.fields.port')}</Label>
              <Input
                id="edit_rule_dst_port"
                value={form.dest_port}
                onChange={(e) => updateField('dest_port', e.target.value)}
              />
            </div>
          </div>

          {/* Protocol + Action */}
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-2">
              <Label>{t('FirewallPage.ruleColumns.protocol')}</Label>
              <Select value={form.protocol} onValueChange={(v) => updateField('protocol', v)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="any">ANY</SelectItem>
                  <SelectItem value="tcp">TCP</SelectItem>
                  <SelectItem value="udp">UDP</SelectItem>
                  <SelectItem value="icmp">ICMP</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label>{t('FirewallPage.ruleColumns.action')}</Label>
              <Select value={form.action} onValueChange={(v) => updateField('action', v)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="allow">{t('FirewallPage.action.allow')}</SelectItem>
                  <SelectItem value="deny">{t('FirewallPage.action.deny')}</SelectItem>
                  <SelectItem value="reject">{t('FirewallPage.action.reject')}</SelectItem>
                  <SelectItem value="log">{t('FirewallPage.action.log')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Description */}
          <div className="grid gap-2">
            <Label htmlFor="edit_rule_desc">{t('FirewallPage.fields.descriptionOptional')}</Label>
            <Input
              id="edit_rule_desc"
              placeholder={t('FirewallPage.fields.descriptionPlaceholder')}
              value={form.description}
              onChange={(e) => updateField('description', e.target.value)}
            />
          </div>

          {/* Enabled */}
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="edit_rule_enabled"
              checked={form.is_enabled}
              onChange={(e) => updateField('is_enabled', e.target.checked)}
              className="h-4 w-4 rounded border-input"
            />
            <Label htmlFor="edit_rule_enabled">{t('FirewallPage.status.enabled')}</Label>
          </div>
        </div>

        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('common:cancel')}
          </Button>
          <Button onClick={handleSubmit} disabled={!canSubmit || isSubmitting}>
            {isSubmitting ? t('common:saving') : t('common:save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// =============================================================================
// Tab ↔ URL mapping
// =============================================================================

const TAB_PATHS: Record<string, string> = {
  dashboard: '/firewall',
  gateways: '/firewall/gateways',
  rules: '/firewall/rules',
  'nat-rules': '/firewall/nat-rules',
  vpn: '/firewall/vpn',
  ids: '/firewall/ids',
  logs: '/firewall/logs',
  orchestration: '/firewall/orchestration',
};

const PATH_TO_TAB: Record<string, string> = {};
for (const [tab, path] of Object.entries(TAB_PATHS)) {
  PATH_TO_TAB[path] = tab;
}

function resolveTabFromPath(pathname: string): string {
  const clean = pathname.replace(/\/+$/, '') || '/firewall';
  if (PATH_TO_TAB[clean]) return PATH_TO_TAB[clean];
  return 'dashboard';
}

// =============================================================================
// Utility
// =============================================================================

function timeAgo(dateStr?: string | null): string {
  if (!dateStr) return 'Never';
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function formatBytes(bytes?: number | null): string {
  if (!bytes) return '-';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1073741824).toFixed(2)} GB`;
}

// =============================================================================
// Main Page
// =============================================================================

export default function FirewallPage() {
  const { t } = useTranslation('firewall');
  const location = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [showAddGateway, setShowAddGateway] = useState(false);
  const [editingGateway, setEditingGateway] = useState<GatewayConnection | null>(null);
  const [editingRule, setEditingRule] = useState<FirewallRule | null>(null);
  const [vendorFilter, setVendorFilter] = useState<string>('all');

  // Derive active tab from URL
  const activeTab = resolveTabFromPath(location.pathname);

  const handleTabChange = useCallback(
    (tab: string) => {
      navigate(TAB_PATHS[tab] || '/firewall');
    },
    [navigate],
  );

  // Site context
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ─────────────────────────────────────────────────────────────────
  // API Queries
  // ─────────────────────────────────────────────────────────────────

  // Gateways
  const { data: gatewaysRes, isLoading: gatewaysLoading, isError: gatewaysError, refetch: refetchGateways } = useQuery({
    queryKey: ['fw-gateways', { siteId: selectedSiteId }],
    queryFn: () => gatewayApi.getAll({ limit: 200, ...(selectedSiteId ? { site_id: selectedSiteId } : {}) }),
    refetchInterval: 30_000,
    staleTime: 10_000,
  });

  const { data: summaryRes, refetch: refetchSummary } = useQuery({
    queryKey: ['fw-gateways-summary', { siteId: selectedSiteId }],
    queryFn: () => gatewayApi.getSummary(selectedSiteId ? { site_id: selectedSiteId } : undefined),
    refetchInterval: 30_000,
  });

  const siteFilter = selectedSiteId ? { site_id: selectedSiteId } : {};

  // Rules
  const { data: rulesRes, isLoading: rulesLoading, isError: rulesError, refetch: refetchRules } = useQuery({
    queryKey: ['fw-rules', { siteId: selectedSiteId }],
    queryFn: () => firewallApi.getRules({ limit: 500, ...siteFilter }),
    refetchInterval: 30_000,
  });

  // NAT
  const { data: natRes, isLoading: natLoading, isError: natError, refetch: refetchNat } = useQuery({
    queryKey: ['fw-nat', { siteId: selectedSiteId }],
    queryFn: () => firewallApi.getNATRules({ limit: 500, ...siteFilter }),
    refetchInterval: 30_000,
  });

  // VPN
  const { data: vpnRes, isLoading: vpnLoading, isError: vpnError, refetch: refetchVpn } = useQuery({
    queryKey: ['fw-vpn', { siteId: selectedSiteId }],
    queryFn: () => firewallApi.getVPNTunnels({ limit: 200, ...siteFilter }),
    refetchInterval: 15_000,
  });

  const { data: vpnStatsRes } = useQuery({
    queryKey: ['fw-vpn-stats', { siteId: selectedSiteId }],
    queryFn: () => firewallApi.getVPNStats(siteFilter),
    refetchInterval: 15_000,
  });

  // IDS
  const { data: alertsRes, isLoading: alertsLoading, isError: alertsError, refetch: refetchAlerts } = useQuery({
    queryKey: ['fw-alerts', { siteId: selectedSiteId }],
    queryFn: () => firewallApi.getAlerts({ limit: 500, ...siteFilter }),
    refetchInterval: 15_000,
  });

  const { data: alertStatsRes } = useQuery({
    queryKey: ['fw-alert-stats', { siteId: selectedSiteId }],
    queryFn: () => firewallApi.getAlertStats(siteFilter),
    refetchInterval: 15_000,
  });

  // Logs
  const { data: logsRes, isLoading: logsLoading, isError: logsError, refetch: refetchLogs } = useQuery({
    queryKey: ['fw-logs', { siteId: selectedSiteId }],
    queryFn: () => firewallApi.getLogs({ limit: 200, ...siteFilter }),
    refetchInterval: 10_000,
  });

  // Sites (for gateway assignment dropdown)
  const { data: sitesData } = useQuery({
    queryKey: ['sites-list'],
    queryFn: async () => (await sitesApiV2.list({ page_size: 200 })).data,
    staleTime: 60_000,
  });
  const sites: Site[] = sitesData?.items ?? [];

  // ─────────────────────────────────────────────────────────────────
  // Gateway Mutations
  // ─────────────────────────────────────────────────────────────────

  const createGatewayMutation = useMutation({
    mutationFn: (data: GatewayConnectionCreate) => gatewayApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fw-gateways'] });
      queryClient.invalidateQueries({ queryKey: ['fw-gateways-summary'] });
      setShowAddGateway(false);
    },
    onError: (err: any) => {
      toast({ title: t('FirewallPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('FirewallPage.toast.operationFailed'), variant: 'destructive' });
    },
  });

  const updateGatewayMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: import('@/lib/api').GatewayConnectionUpdate }) =>
      gatewayApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fw-gateways'] });
      queryClient.invalidateQueries({ queryKey: ['fw-gateways-summary'] });
      setEditingGateway(null);
    },
    onError: (err: any) => {
      toast({ title: t('FirewallPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('FirewallPage.toast.operationFailed'), variant: 'destructive' });
    },
  });

  const deleteGatewayMutation = useMutation({
    mutationFn: (id: string) => gatewayApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fw-gateways'] });
      queryClient.invalidateQueries({ queryKey: ['fw-gateways-summary'] });
    },
    onError: (err: any) => {
      toast({ title: t('FirewallPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('FirewallPage.toast.operationFailed'), variant: 'destructive' });
    },
  });

  const syncGatewayMutation = useMutation({
    mutationFn: (id: string) => gatewayApi.triggerSync(id, false),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fw-gateways'] });
    },
    onError: (err: any) => {
      toast({ title: t('FirewallPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('FirewallPage.toast.operationFailed'), variant: 'destructive' });
    },
  });

  const testConnectionMutation = useMutation({
    mutationFn: (data: GatewayTestRequest) => gatewayApi.testConnection(data),
    onError: (err: any) => {
      toast({ title: t('FirewallPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('FirewallPage.toast.operationFailed'), variant: 'destructive' });
    },
  });

  const testExistingMutation = useMutation({
    mutationFn: ({ id, overrides }: { id: string; overrides?: { verify_ssl?: boolean; host?: string; port?: number } }) =>
      gatewayApi.testExisting(id, overrides),
    onSuccess: (res) => {
      const r = res.data;
      if (r.success) {
        toast({ title: t('FirewallPage.toast.connectionOk'), description: `${r.hostname || t('FirewallPage.toast.gatewayFallback')} · ${r.version || ''} (${r.latency_ms}ms)` });
      } else {
        toast({ title: t('FirewallPage.toast.connectionFailed'), description: r.message, variant: 'destructive' });
      }
      queryClient.invalidateQueries({ queryKey: ['fw-gateways'] });
    },
    onError: (err: any) => {
      toast({ title: t('FirewallPage.toast.testFailed'), description: err?.response?.data?.detail || t('FirewallPage.toast.connectionTestFailed'), variant: 'destructive' });
    },
  });

  // ─────────────────────────────────────────────────────────────────
  // Rule Mutations
  // ─────────────────────────────────────────────────────────────────

  const deleteRuleMutation = useMutation({
    mutationFn: (id: string) => firewallApi.deleteRule(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['fw-rules'] }),
    onError: (err: any) => {
      toast({ title: t('FirewallPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('FirewallPage.toast.operationFailed'), variant: 'destructive' });
    },
  });

  const updateRuleMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) => firewallApi.updateRule(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fw-rules'] });
      setEditingRule(null);
    },
    onError: (err: any) => {
      toast({ title: t('FirewallPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('FirewallPage.toast.operationFailed'), variant: 'destructive' });
    },
  });

  // ─────────────────────────────────────────────────────────────────
  // IDS Mutations
  // ─────────────────────────────────────────────────────────────────

  const acknowledgeMutation = useMutation({
    mutationFn: (id: string) => firewallApi.acknowledgeAlert(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fw-alerts'] });
      queryClient.invalidateQueries({ queryKey: ['fw-alert-stats'] });
    },
    onError: (err: any) => {
      toast({ title: t('FirewallPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('FirewallPage.toast.operationFailed'), variant: 'destructive' });
    },
  });

  // ─────────────────────────────────────────────────────────────────
  // Derived data
  // ─────────────────────────────────────────────────────────────────

  const rawGateways = gatewaysRes?.data;
  const gateways: GatewayConnection[] = Array.isArray(rawGateways) ? rawGateways : rawGateways?.items ?? [];
  const summary: GatewaySummary | null = summaryRes?.data ?? null;
  const rawRules = rulesRes?.data;
  const rules: FirewallRule[] = Array.isArray(rawRules) ? rawRules : rawRules?.items ?? [];
  const rawNat = natRes?.data;
  const natRules: NATRule[] = Array.isArray(rawNat) ? rawNat : rawNat?.items ?? [];
  const rawVpn = vpnRes?.data;
  const vpnTunnels: VPNTunnel[] = Array.isArray(rawVpn) ? rawVpn : rawVpn?.items ?? [];
  const vpnStats = vpnStatsRes?.data ?? { total: vpnTunnels.length, up: 0, down: 0, error: 0 };
  const rawAlerts = alertsRes?.data;
  const alerts: IDSAlert[] = Array.isArray(rawAlerts) ? rawAlerts : rawAlerts?.items ?? [];
  const alertStats = alertStatsRes?.data ?? {
    total: alerts.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unacknowledged: alerts.filter((a) => !a.is_acknowledged).length,
  };
  const rawLogs = logsRes?.data;
  const logs: FirewallLog[] = Array.isArray(rawLogs) ? rawLogs : rawLogs?.items ?? [];

  const hasQueryError = gatewaysError || rulesError || natError || vpnError || alertsError || logsError;

  // Filtered gateways (vendor dropdown only · text search handled by DataTable)
  const filteredGateways = vendorFilter === 'all'
    ? gateways
    : gateways.filter((gw) => gw.vendor === vendorFilter);

  // ─────────────────────────────────────────────────────────────────
  // Gateway Columns
  // ─────────────────────────────────────────────────────────────────

  const gatewayColumns: DataTableColumn<GatewayConnection>[] = [
    {
      id: 'name',
      header: t('FirewallPage.gatewayColumns.gateway'),
      cell: (gw) => (
        <div className="flex items-center gap-3">
          <div className={cn('p-2 rounded-lg', gw.is_online ? 'bg-emerald-500/10' : 'bg-muted')}>
            <Server className={cn('h-4 w-4', gw.is_online ? 'text-emerald-500' : 'text-muted-foreground')} />
          </div>
          <div>
            <div className="font-medium">{gw.name}</div>
            <div className="text-sm text-muted-foreground">
              {gw.detected_hostname || gw.host}
              {gw.detected_version && ` · v${gw.detected_version}`}
            </div>
          </div>
        </div>
      ),
    },
    {
      id: 'vendor',
      header: t('FirewallPage.gatewayColumns.type'),
      cell: (gw) => <VendorBadge vendor={gw.vendor} />,
    },
    {
      id: 'site',
      header: t('FirewallPage.gatewayColumns.site'),
      cell: (gw) => {
        if (!gw.site_id) return <span className="text-sm text-muted-foreground">-</span>;
        const site = sites.find((s) => s.id === gw.site_id);
        return <span className="text-sm">{site?.name ?? '-'}</span>;
      },
    },
    {
      id: 'host',
      header: t('FirewallPage.gatewayColumns.address'),
      cell: (gw) => <code className="text-sm">{gw.host}:{gw.port}</code>,
    },
    {
      id: 'status',
      header: t('FirewallPage.gatewayColumns.status'),
      cell: (gw) => (
        <Badge variant="outline" className={cn(
          'gap-1',
          gw.is_online
            ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
            : 'bg-red-500/10 text-red-500 border-red-500/20',
        )}>
          {gw.is_online ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
          {gw.is_online ? t('FirewallPage.status.online') : t('FirewallPage.status.offline')}
        </Badge>
      ),
    },
    {
      id: 'sync',
      header: t('FirewallPage.gatewayColumns.sync'),
      cell: (gw) => <SyncStatusBadge status={gw.sync_status} />,
    },
    {
      id: 'last_seen',
      header: t('FirewallPage.gatewayColumns.lastSeen'),
      cell: (gw) => <span className="text-sm text-muted-foreground">{timeAgo(gw.last_seen_at)}</span>,
    },
    {
      id: 'actions',
      header: '',
      cell: (gw) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon"><MoreHorizontal className="h-4 w-4" /></Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => navigate(`/firewall/gateways/${gw.id}`)}>
              <Eye className="h-4 w-4 mr-2" />{t('FirewallPage.actions.viewDetails')}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => setEditingGateway(gw)}>
              <Edit className="h-4 w-4 mr-2" />{t('FirewallPage.actions.editGateway')}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => syncGatewayMutation.mutate(gw.id)}>
              <RefreshCw className="h-4 w-4 mr-2" />{t('FirewallPage.actions.syncNow')}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => testExistingMutation.mutate({ id: gw.id })}>
              <Zap className="h-4 w-4 mr-2" />{t('FirewallPage.actions.testConnection')}
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="text-red-500 focus:text-red-500"
              onClick={() => {
                if (window.confirm(t('FirewallPage.confirm.deleteGateway', { name: gw.name })))
                  deleteGatewayMutation.mutate(gw.id);
              }}
            >
              <Trash2 className="h-4 w-4 mr-2" />{t('FirewallPage.actions.delete')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ];

  // ─────────────────────────────────────────────────────────────────
  // Rule Columns
  // ─────────────────────────────────────────────────────────────────

  const ruleColumns: DataTableColumn<FirewallRule>[] = [
    {
      id: 'rule_order',
      header: '#',
      cell: (rule) => <span className="font-mono text-sm">{rule.rule_order}</span>,
    },
    {
      id: 'name',
      header: t('FirewallPage.ruleColumns.rule'),
      cell: (rule) => (
        <div>
          <div className="font-medium">{rule.name}</div>
          {rule.description && <div className="text-xs text-muted-foreground truncate max-w-xs">{rule.description}</div>}
        </div>
      ),
    },
    {
      id: 'source',
      header: t('FirewallPage.ruleColumns.source'),
      cell: (rule) => (
        <div className="flex items-center gap-2">
          <Globe className="h-3.5 w-3.5 text-muted-foreground" />
          <code className="text-sm">{rule.source_address || 'any'}</code>
          {rule.source_port && <span className="text-muted-foreground text-xs">:{rule.source_port}</span>}
        </div>
      ),
    },
    {
      id: 'arrow',
      header: '',
      cell: () => <ArrowRight className="h-4 w-4 text-muted-foreground" />,
    },
    {
      id: 'destination',
      header: t('FirewallPage.ruleColumns.destination'),
      cell: (rule) => (
        <div className="flex items-center gap-2">
          <Server className="h-3.5 w-3.5 text-muted-foreground" />
          <code className="text-sm">{rule.dest_address || 'any'}</code>
          {rule.dest_port && <span className="text-muted-foreground text-xs">:{rule.dest_port}</span>}
        </div>
      ),
    },
    {
      id: 'protocol',
      header: t('FirewallPage.ruleColumns.protocol'),
      cell: (rule) => <Badge variant="secondary">{(rule.protocol || 'ANY').toUpperCase()}</Badge>,
    },
    {
      id: 'action',
      header: t('FirewallPage.ruleColumns.action'),
      cell: (rule) => <ActionBadge action={rule.action} />,
    },
    {
      id: 'enabled',
      header: t('FirewallPage.ruleColumns.status'),
      cell: (rule) => (
        <Badge variant="outline" className={cn(
          rule.is_enabled ? 'bg-emerald-500/10 text-emerald-500' : 'bg-muted-foreground/10 text-muted-foreground',
        )}>
          {rule.is_enabled ? t('FirewallPage.status.enabled') : t('FirewallPage.status.disabled')}
        </Badge>
      ),
    },
    {
      id: 'hits',
      header: t('FirewallPage.ruleColumns.hits'),
      cell: (rule) => <span className="text-sm font-mono text-muted-foreground">{rule.hit_count?.toLocaleString() ?? 0}</span>,
    },
    {
      id: 'actions',
      header: '',
      cell: (rule) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon"><MoreHorizontal className="h-4 w-4" /></Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => setEditingRule(rule)}><Edit className="h-4 w-4 mr-2" />{t('FirewallPage.actions.editRule')}</DropdownMenuItem>
            <DropdownMenuItem onClick={() => navigate('/firewall/logs')}><Eye className="h-4 w-4 mr-2" />{t('FirewallPage.actions.viewLogs')}</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="text-red-500 focus:text-red-500"
              onClick={() => {
                if (window.confirm(t('FirewallPage.confirm.deleteRule', { name: rule.name })))
                  deleteRuleMutation.mutate(rule.id);
              }}
            >
              <Trash2 className="h-4 w-4 mr-2" />{t('FirewallPage.actions.deleteRule')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ];

  // ─────────────────────────────────────────────────────────────────
  // NAT Columns
  // ─────────────────────────────────────────────────────────────────

  const natColumns: DataTableColumn<NATRule>[] = [
    {
      id: 'name',
      header: t('FirewallPage.natColumns.rule'),
      cell: (rule) => (
        <div>
          <div className="font-medium">{rule.name}</div>
          {rule.description && <div className="text-xs text-muted-foreground truncate max-w-xs">{rule.description}</div>}
        </div>
      ),
    },
    {
      id: 'type',
      header: t('FirewallPage.natColumns.type'),
      cell: (rule) => (
        <Badge variant="secondary" className="uppercase">{rule.nat_type}</Badge>
      ),
    },
    {
      id: 'original',
      header: t('FirewallPage.natColumns.original'),
      cell: (rule) => (
        <div>
          <code className="text-sm">{rule.original_address}</code>
          {rule.original_port && <span className="text-muted-foreground text-xs">:{rule.original_port}</span>}
        </div>
      ),
    },
    {
      id: 'arrow',
      header: '',
      cell: () => <ArrowRight className="h-4 w-4 text-muted-foreground" />,
    },
    {
      id: 'translated',
      header: t('FirewallPage.natColumns.translated'),
      cell: (rule) => (
        <div>
          <code className="text-sm">{rule.translated_address}</code>
          {rule.translated_port && <span className="text-muted-foreground text-xs">:{rule.translated_port}</span>}
        </div>
      ),
    },
    {
      id: 'protocol',
      header: t('FirewallPage.natColumns.protocol'),
      cell: (rule) => <Badge variant="secondary">{(rule.protocol || 'ANY').toUpperCase()}</Badge>,
    },
    {
      id: 'interface',
      header: t('FirewallPage.natColumns.interface'),
      cell: (rule) => <span className="text-sm text-muted-foreground">{rule.interface || '-'}</span>,
    },
    {
      id: 'enabled',
      header: t('FirewallPage.natColumns.status'),
      cell: (rule) => (
        <Badge variant="outline" className={cn(
          rule.is_enabled ? 'bg-emerald-500/10 text-emerald-500' : 'bg-muted-foreground/10 text-muted-foreground',
        )}>
          {rule.is_enabled ? t('FirewallPage.status.enabled') : t('FirewallPage.status.disabled')}
        </Badge>
      ),
    },
  ];

  // ─────────────────────────────────────────────────────────────────
  // VPN Columns
  // ─────────────────────────────────────────────────────────────────

  const vpnColumns: DataTableColumn<VPNTunnel>[] = [
    {
      id: 'name',
      header: t('FirewallPage.vpnColumns.tunnel'),
      cell: (tunnel) => (
        <div className="flex items-center gap-3">
          <div className={cn('p-2 rounded-lg', tunnel.status === 'up' ? 'bg-emerald-500/10' : 'bg-muted')}>
            <Lock className={cn('h-4 w-4', tunnel.status === 'up' ? 'text-emerald-500' : 'text-muted-foreground')} />
          </div>
          <div>
            <div className="font-medium">{tunnel.name}</div>
            <div className="text-sm text-muted-foreground">{tunnel.vpn_type?.toUpperCase()}</div>
          </div>
        </div>
      ),
    },
    {
      id: 'local',
      header: t('FirewallPage.vpnColumns.local'),
      cell: (tunnel) => {
        const subnets = Array.isArray(tunnel.local_subnets) ? tunnel.local_subnets.join(', ') : tunnel.local_subnets;
        return <code className="text-sm">{subnets || tunnel.local_address || '-'}</code>;
      },
    },
    {
      id: 'remote',
      header: t('FirewallPage.vpnColumns.remote'),
      cell: (tunnel) => {
        const subnets = Array.isArray(tunnel.remote_subnets) ? tunnel.remote_subnets.join(', ') : tunnel.remote_subnets;
        return (
          <div>
            <code className="text-sm">{subnets || '-'}</code>
            {tunnel.remote_address && <div className="text-xs text-muted-foreground">{tunnel.remote_address}</div>}
          </div>
        );
      },
    },
    {
      id: 'status',
      header: t('FirewallPage.vpnColumns.status'),
      cell: (tunnel) => <VPNStatusBadge status={tunnel.status} />,
    },
    {
      id: 'traffic',
      header: t('FirewallPage.vpnColumns.traffic'),
      cell: (tunnel) => (
        <div className="text-sm text-muted-foreground">
          <span className="text-emerald-500">↓{formatBytes(tunnel.bytes_in)}</span>
          {' / '}
          <span className="text-blue-500">↑{formatBytes(tunnel.bytes_out)}</span>
        </div>
      ),
    },
    {
      id: 'uptime',
      header: t('FirewallPage.vpnColumns.connected'),
      cell: (tunnel) => (
        <span className="text-sm text-muted-foreground">
          {tunnel.last_connected ? timeAgo(tunnel.last_connected) : '-'}
        </span>
      ),
    },
    // NOTE: VPN per-row actions (View Traffic / Settings) intentionally
    // omitted, there is no VPN-traffic detail view or VPN-tunnel edit dialog
    // yet, and the dropdown items were dead no-ops. Traffic is already shown
    // inline in the `traffic` column. Re-add when those views exist.
  ];

  // ─────────────────────────────────────────────────────────────────
  // Alert Columns
  // ─────────────────────────────────────────────────────────────────

  const alertColumns: DataTableColumn<IDSAlert>[] = [
    {
      id: 'severity',
      header: t('FirewallPage.alertColumns.severity'),
      cell: (a) => <SeverityBadge severity={a.severity} />,
    },
    {
      id: 'time',
      header: t('FirewallPage.alertColumns.time'),
      cell: (a) => <span className="text-sm text-muted-foreground">{new Date(a.timestamp).toLocaleString()}</span>,
    },
    {
      id: 'alert',
      header: t('FirewallPage.alertColumns.alert'),
      cell: (a) => (
        <div>
          <div className="font-medium">{a.signature_name}</div>
          {a.category && <div className="text-xs text-muted-foreground">{a.category}</div>}
        </div>
      ),
    },
    {
      id: 'source',
      header: t('FirewallPage.alertColumns.source'),
      cell: (a) => (
        <div>
          <code className="text-sm">{a.source_ip}</code>
          {a.source_port && <span className="text-xs text-muted-foreground">:{a.source_port}</span>}
        </div>
      ),
    },
    {
      id: 'destination',
      header: t('FirewallPage.alertColumns.destination'),
      cell: (a) => (
        <div>
          <code className="text-sm">{a.dest_ip}</code>
          {a.dest_port && <span className="text-xs text-muted-foreground">:{a.dest_port}</span>}
        </div>
      ),
    },
    {
      id: 'status',
      header: t('FirewallPage.alertColumns.status'),
      cell: (a) => (
        a.is_acknowledged ? (
          <Badge variant="outline" className="bg-muted-foreground/10 text-muted-foreground">{t('FirewallPage.alertStatus.acknowledged')}</Badge>
        ) : (
          <Badge variant="outline" className="bg-amber-500/10 text-amber-500 border-amber-500/20">{t('FirewallPage.alertStatus.open')}</Badge>
        )
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: (a) => (
        <div className="flex items-center gap-2">
          {!a.is_acknowledged && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => acknowledgeMutation.mutate(a.id)}
              disabled={acknowledgeMutation.isPending}
            >
              {t('FirewallPage.actions.acknowledge')}
            </Button>
          )}
        </div>
      ),
    },
  ];

  // ─────────────────────────────────────────────────────────────────
  // Log Columns
  // ─────────────────────────────────────────────────────────────────

  const logColumns: DataTableColumn<FirewallLog>[] = [
    {
      id: 'time',
      header: t('FirewallPage.logColumns.time'),
      cell: (l) => <span className="text-sm text-muted-foreground font-mono">{new Date(l.timestamp).toLocaleString()}</span>,
    },
    {
      id: 'action',
      header: t('FirewallPage.logColumns.action'),
      cell: (l) => <ActionBadge action={l.action} />,
    },
    {
      id: 'protocol',
      header: t('FirewallPage.logColumns.proto'),
      cell: (l) => <Badge variant="secondary">{(l.protocol || 'ANY').toUpperCase()}</Badge>,
    },
    {
      id: 'source',
      header: t('FirewallPage.logColumns.source'),
      cell: (l) => (
        <div>
          <code className="text-sm">{l.source_ip}</code>
          {l.source_port && <span className="text-xs text-muted-foreground">:{l.source_port}</span>}
          {l.source_zone && <div className="text-xs text-muted-foreground">{l.source_zone}</div>}
        </div>
      ),
    },
    {
      id: 'destination',
      header: t('FirewallPage.logColumns.destination'),
      cell: (l) => (
        <div>
          <code className="text-sm">{l.dest_ip}</code>
          {l.dest_port && <span className="text-xs text-muted-foreground">:{l.dest_port}</span>}
          {l.dest_zone && <div className="text-xs text-muted-foreground">{l.dest_zone}</div>}
        </div>
      ),
    },
    {
      id: 'bytes',
      header: t('FirewallPage.logColumns.bytes'),
      cell: (l) => (
        <div className="text-sm text-muted-foreground font-mono">
          {(l.bytes_sent || l.bytes_received)
            ? <><span className="text-emerald-500">↓{formatBytes(l.bytes_received)}</span>{' / '}<span className="text-blue-500">↑{formatBytes(l.bytes_sent)}</span></>
            : '-'
          }
        </div>
      ),
    },
  ];

  // ─────────────────────────────────────────────────────────────────
  // Tab: Dashboard
  // ─────────────────────────────────────────────────────────────────

  const renderDashboard = () => (
    <div className="space-y-6">
      {/* Gateway summary */}
      <div>
        <h3 className="text-lg font-semibold mb-3">{t('FirewallPage.dashboard.gatewayIntegrations')}</h3>
        {gateways.length === 0 ? (
          <Card>
            <CardContent noOffset className="py-4">
              <EmptyState
                icon={Server}
                title={t('FirewallPage.dashboard.emptyTitle')}
                description={t('FirewallPage.dashboard.emptyDescription')}
                action={{ label: t('FirewallPage.actions.addGateway'), onClick: () => setShowAddGateway(true) }}
              />
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {gateways.slice(0, 6).map((gw) => (
              <Card
                key={gw.id}
                className="cursor-pointer hover:border-primary/50 transition-colors"
                onClick={() => navigate(`/firewall/gateways/${gw.id}`)}
              >
                <CardContent noOffset>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <div className={cn('p-2 rounded-lg', gw.is_online ? 'bg-emerald-500/10' : 'bg-muted')}>
                        <Server className={cn('h-4 w-4', gw.is_online ? 'text-emerald-500' : 'text-muted-foreground')} />
                      </div>
                      <div>
                        <p className="font-medium">{gw.name}</p>
                        <p className="text-xs text-muted-foreground">{gw.detected_hostname || gw.host}</p>
                      </div>
                    </div>
                    <VendorBadge vendor={gw.vendor} />
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <Badge variant="outline" className={cn(
                      'gap-1',
                      gw.is_online ? 'bg-emerald-500/10 text-emerald-500' : 'bg-red-500/10 text-red-500',
                    )}>
                      {gw.is_online ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
                      {gw.is_online ? t('FirewallPage.status.online') : t('FirewallPage.status.offline')}
                    </Badge>
                    <span className="text-muted-foreground">
                      {gw.detected_version && `v${gw.detected_version}`}
                    </span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* Quick stats grid */}
      <div>
        <h3 className="text-lg font-semibold mb-3">{t('FirewallPage.dashboard.securityOverview')}</h3>
        <StatsGrid
          columns={4}
          stats={[
            { title: t('FirewallPage.stats.firewallRules'), value: rules.length, icon: Shield, variant: 'primary' },
            { title: t('FirewallPage.stats.natRules'), value: natRules.length, icon: Network, variant: 'primary' },
            {
              title: t('FirewallPage.stats.vpnConnected'),
              value: vpnStats.up ?? vpnTunnels.filter((t) => t.status === 'up').length,
              icon: Lock,
              variant: 'success',
            },
            {
              title: t('FirewallPage.stats.idsAlerts'),
              value: alertStats.unacknowledged ?? 0,
              icon: ShieldAlert,
              variant: (alertStats.critical ?? 0) > 0 ? 'destructive' : 'warning',
            },
          ]}
        />
      </div>

      {/* Recent alerts */}
      {alerts.length > 0 && (
        <Card className="border-border/50">
          <CardHeader className="pb-4">
            <CardTitle>{t('FirewallPage.dashboard.recentAlerts')}</CardTitle>
          </CardHeader>
            <DataTable
              data={alerts.filter((a) => !a.is_acknowledged).slice(0, 5)}
              columns={alertColumns}
              searchable={false}
              itemName={t('FirewallPage.itemNames.alerts')}
              embedded
            />
        </Card>
      )}

      {/* Recent logs */}
      {logs.length > 0 && (
        <Card className="border-border/50">
          <CardHeader className="pb-4">
            <CardTitle>{t('FirewallPage.dashboard.recentTraffic')}</CardTitle>
          </CardHeader>
            <DataTable
              data={logs.slice(0, 10)}
              columns={logColumns}
              searchable={false}
              itemName={t('FirewallPage.itemNames.logEntries')}
              embedded
            />
        </Card>
      )}
    </div>
  );

  // ─────────────────────────────────────────────────────────────────
  // Tab: Gateways
  // ─────────────────────────────────────────────────────────────────

  const renderGateways = () => (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Select value={vendorFilter} onValueChange={setVendorFilter}>
          <SelectTrigger className="w-[160px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('FirewallPage.vendorFilter.all')}</SelectItem>
            <SelectItem value="opnsense">OPNsense</SelectItem>
            <SelectItem value="pfsense">pfSense</SelectItem>
            <SelectItem value="mikrotik">MikroTik</SelectItem>
            <SelectItem value="openwrt">OpenWRT</SelectItem>
          </SelectContent>
        </Select>
        <Button onClick={() => setShowAddGateway(true)}>
          <Plus className="h-4 w-4 mr-2" />
          {t('FirewallPage.actions.addGateway')}
        </Button>
      </div>

      {/* Summary cards */}
      {summary && (
        <StatsGrid
          columns={4}
          stats={[
            { title: t('FirewallPage.stats.totalGateways'), value: summary.total_gateways, icon: Server, variant: 'primary' },
            { title: t('FirewallPage.stats.online'), value: summary.online, icon: Wifi, variant: 'success' },
            {
              title: t('FirewallPage.stats.offline'),
              value: summary.offline,
              icon: WifiOff,
              variant: summary.offline > 0 ? 'destructive' : 'default',
            },
            { title: t('FirewallPage.stats.syncOk'), value: summary.sync_success, icon: CheckCircle, variant: 'success' },
          ]}
        />
      )}

      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('FirewallPage.gateways.title')}</CardTitle>
        </CardHeader>
        <DataTable
          data={filteredGateways}
          columns={gatewayColumns}
          isLoading={gatewaysLoading}
          searchable
          searchPlaceholder={t('FirewallPage.gateways.searchPlaceholder')}
          itemName={t('FirewallPage.itemNames.gateways')}
          embedded
        />
      </Card>
    </div>
  );

  // ─────────────────────────────────────────────────────────────────
  // Tab: Rules
  // ─────────────────────────────────────────────────────────────────

  const renderRules = () => (
    <div className="space-y-6">
      <Card className="border-border/50">
        <CardHeader className="pb-4 flex flex-row items-center justify-between">
          <CardTitle>{t('FirewallPage.rules.title')}</CardTitle>
          <Button variant="outline" size="sm" onClick={() => refetchRules()} disabled={rulesLoading}>
            <RefreshCw className={cn('h-4 w-4 mr-2', rulesLoading && 'animate-spin')} />
            {t('FirewallPage.actions.refresh')}
          </Button>
        </CardHeader>
        <DataTable
          data={rules}
          columns={ruleColumns}
          isLoading={rulesLoading}
          searchable
          searchPlaceholder={t('FirewallPage.rules.searchPlaceholder')}
          itemName={t('FirewallPage.itemNames.firewallRules')}
          embedded
        />
      </Card>
    </div>
  );

  // ─────────────────────────────────────────────────────────────────
  // Tab: NAT
  // ─────────────────────────────────────────────────────────────────

  const renderNAT = () => (
    <div className="space-y-6">
      <Card className="border-border/50">
        <CardHeader className="pb-4 flex flex-row items-center justify-between">
          <CardTitle>{t('FirewallPage.nat.title')}</CardTitle>
          <Button variant="outline" size="sm" onClick={() => refetchNat()} disabled={natLoading}>
            <RefreshCw className={cn('h-4 w-4 mr-2', natLoading && 'animate-spin')} />
            {t('FirewallPage.actions.refresh')}
          </Button>
        </CardHeader>
        <DataTable
          data={natRules}
          columns={natColumns}
          isLoading={natLoading}
          searchable
          searchPlaceholder={t('FirewallPage.nat.searchPlaceholder')}
          itemName={t('FirewallPage.itemNames.natRules')}
          embedded
        />
      </Card>
    </div>
  );

  // ─────────────────────────────────────────────────────────────────
  // Tab: VPN
  // ─────────────────────────────────────────────────────────────────

  const renderVPN = () => (
    <div className="space-y-6">
      {/* VPN stats */}
      <StatsGrid
        columns={4}
        stats={[
          { title: t('FirewallPage.stats.totalTunnels'), value: vpnStats.total ?? vpnTunnels.length, icon: Lock, variant: 'primary' },
          {
            title: t('FirewallPage.stats.connected'),
            value: vpnStats.up ?? vpnTunnels.filter((t) => t.status === 'up').length,
            icon: CheckCircle,
            variant: 'success',
          },
          {
            title: t('FirewallPage.stats.disconnected'),
            value: vpnStats.down ?? vpnTunnels.filter((t) => t.status === 'down').length,
            icon: XCircle,
            variant: 'destructive',
          },
          {
            title: t('FirewallPage.stats.errors'),
            value: vpnStats.error ?? vpnTunnels.filter((t) => t.status === 'error').length,
            icon: AlertCircle,
            variant: (vpnStats.error ?? 0) > 0 ? 'destructive' : 'warning',
          },
        ]}
      />

      <Card className="border-border/50">
        <CardHeader className="pb-4 flex flex-row items-center justify-between">
          <div>
            <CardTitle>{t('FirewallPage.vpn.title')}</CardTitle>
            <CardDescription>{t('FirewallPage.vpn.description')}</CardDescription>
          </div>
          <Button variant="outline" size="sm" onClick={() => refetchVpn()} disabled={vpnLoading}>
            <RefreshCw className={cn('h-4 w-4 mr-2', vpnLoading && 'animate-spin')} />
            {t('FirewallPage.actions.refresh')}
          </Button>
        </CardHeader>
        <DataTable
          data={vpnTunnels}
          columns={vpnColumns}
          isLoading={vpnLoading}
          searchable
          searchPlaceholder={t('FirewallPage.vpn.searchPlaceholder')}
          itemName={t('FirewallPage.itemNames.vpnTunnels')}
          embedded
        />
      </Card>
    </div>
  );

  // ─────────────────────────────────────────────────────────────────
  // Tab: IDS
  // ─────────────────────────────────────────────────────────────────

  const renderIDS = () => (
    <div className="space-y-6">
      {/* Alert stats */}
      <StatsGrid
        columns={4}
        stats={[
          { title: t('FirewallPage.stats.totalAlerts'), value: alertStats.total, icon: ShieldAlert, variant: 'warning' },
          {
            title: t('FirewallPage.stats.critical'),
            value: alertStats.critical ?? 0,
            icon: AlertTriangle,
            variant: (alertStats.critical ?? 0) > 0 ? 'destructive' : 'default',
          },
          { title: t('FirewallPage.stats.high'), value: alertStats.high ?? 0, icon: AlertCircle, variant: 'warning' },
          { title: t('FirewallPage.stats.medium'), value: alertStats.medium ?? 0, icon: AlertCircle, variant: 'warning' },
          { title: t('FirewallPage.stats.unacknowledged'), value: alertStats.unacknowledged ?? 0, icon: Eye, variant: 'primary' },
        ]}
      />

      <Card className="border-border/50">
        <CardHeader className="pb-4 flex flex-row items-center justify-between">
          <div>
            <CardTitle>{t('FirewallPage.ids.title')}</CardTitle>
            <CardDescription>{t('FirewallPage.ids.description')}</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => refetchAlerts()} disabled={alertsLoading}>
              <RefreshCw className={cn('h-4 w-4 mr-2', alertsLoading && 'animate-spin')} />
              {t('FirewallPage.actions.refresh')}
            </Button>
          </div>
        </CardHeader>
        <DataTable
          data={alerts}
          columns={alertColumns}
          isLoading={alertsLoading}
          searchable
          searchPlaceholder={t('FirewallPage.ids.searchPlaceholder')}
          itemName={t('FirewallPage.itemNames.idsAlerts')}
          embedded
        />
      </Card>
    </div>
  );

  // ─────────────────────────────────────────────────────────────────
  // Tab: Logs
  // ─────────────────────────────────────────────────────────────────

  const renderLogs = () => (
    <div className="space-y-6">
      <Card className="border-border/50">
        <CardHeader className="pb-4 flex flex-row items-center justify-between">
          <CardTitle>{t('FirewallPage.logs.title')}</CardTitle>
          <Button variant="outline" size="sm" onClick={() => refetchLogs()} disabled={logsLoading}>
            <RefreshCw className={cn('h-4 w-4 mr-2', logsLoading && 'animate-spin')} />
            {t('FirewallPage.actions.refresh')}
          </Button>
        </CardHeader>
        <DataTable
          data={logs}
          columns={logColumns}
          isLoading={logsLoading}
          searchable
          searchPlaceholder={t('FirewallPage.logs.searchPlaceholder')}
          itemName={t('FirewallPage.itemNames.logEntries')}
          embedded
        />
      </Card>
    </div>
  );

  // ─────────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={Shield}
        title={t('FirewallPage.header.title')}
        subtitle={t('FirewallPage.header.subtitle')}
        onRefresh={() => {
          refetchGateways();
          refetchSummary();
          refetchRules();
          refetchAlerts();
          refetchVpn();
          refetchLogs();
        }}
        refreshing={gatewaysLoading}
        primaryAction={{
          label: t('FirewallPage.actions.addGateway'),
          icon: Plus,
          onClick: () => setShowAddGateway(true),
        }}
      />

      {hasQueryError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('FirewallPage.errors.partialLoad')}</span>
          </CardContent>
        </Card>
      )}

      {/* Top-level summary stats */}
      <StatsGrid
        columns={4}
        stats={[
          {
            title: t('FirewallPage.stats.gateways'),
            value: summary?.total_gateways ?? gateways.length,
            icon: Server,
            variant: 'primary',
          },
          {
            title: t('FirewallPage.stats.online'),
            value: summary?.online ?? gateways.filter((g) => g.is_online).length,
            icon: Wifi,
            variant: 'success',
          },
          {
            title: t('FirewallPage.stats.rules'),
            value: rules.length,
            icon: Shield,
            variant: 'primary',
          },
          {
            title: t('FirewallPage.stats.vpnUp'),
            value: vpnStats.up ?? vpnTunnels.filter((t) => t.status === 'up').length,
            icon: Lock,
            variant: 'success',
          },
          {
            title: t('FirewallPage.stats.idsAlerts'),
            value: alertStats.unacknowledged ?? 0,
            icon: ShieldAlert,
            variant: (alertStats.critical ?? 0) > 0 ? 'destructive' : 'warning',
          },
        ]}
      />

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={handleTabChange}>
        <TabsList>
          <TabsTrigger value="dashboard" className="gap-1.5">
            <BarChart3 className="h-4 w-4" />
            {t('FirewallPage.tabs.dashboard')}
          </TabsTrigger>
          <TabsTrigger value="gateways" className="gap-1.5">
            <Server className="h-4 w-4" />
            {t('FirewallPage.tabs.gateways')}
            {gateways.length > 0 && (
              <Badge variant="secondary" className="ml-1 h-5 min-w-5 p-0 flex items-center justify-center text-xs">
                {gateways.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="rules" className="gap-1.5">
            <Shield className="h-4 w-4" />
            {t('FirewallPage.tabs.rules')}
          </TabsTrigger>
          <TabsTrigger value="nat-rules" className="gap-1.5">
            <Network className="h-4 w-4" />
            {t('FirewallPage.tabs.nat')}
          </TabsTrigger>
          <TabsTrigger value="vpn" className="gap-1.5">
            <Lock className="h-4 w-4" />
            {t('FirewallPage.tabs.vpn')}
          </TabsTrigger>
          <TabsTrigger value="ids" className="gap-1.5 relative">
            <ShieldAlert className="h-4 w-4" />
            {t('FirewallPage.tabs.ids')}
            {(alertStats.unacknowledged ?? 0) > 0 && (
              <Badge variant="destructive" className="ml-1 h-5 min-w-5 p-0 flex items-center justify-center text-xs">
                {alertStats.unacknowledged > 99 ? '99+' : alertStats.unacknowledged}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="logs" className="gap-1.5">
            <FileText className="h-4 w-4" />
            {t('FirewallPage.tabs.logs')}
          </TabsTrigger>
          <TabsTrigger value="orchestration" className="gap-1.5">
            <GitMerge className="h-4 w-4" />
            {t('FirewallPage.tabs.orchestration')}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="dashboard" className="mt-6">{renderDashboard()}</TabsContent>
        <TabsContent value="gateways" className="mt-6">{renderGateways()}</TabsContent>
        <TabsContent value="rules" className="mt-6">{renderRules()}</TabsContent>
        <TabsContent value="nat-rules" className="mt-6">{renderNAT()}</TabsContent>
        <TabsContent value="vpn" className="mt-6">{renderVPN()}</TabsContent>
        <TabsContent value="ids" className="mt-6">{renderIDS()}</TabsContent>
        <TabsContent value="logs" className="mt-6">{renderLogs()}</TabsContent>
      </Tabs>

      {/* ─── Add Gateway Dialog ───────────────────────────────── */}
      <AddGatewayDialog
        open={showAddGateway}
        onOpenChange={setShowAddGateway}
        onSubmit={(data) => createGatewayMutation.mutate(data)}
        onTestConnection={(data) => testConnectionMutation.mutateAsync(data)}
        isSubmitting={createGatewayMutation.isPending}
        testResult={testConnectionMutation.data?.data ?? null}
        isTesting={testConnectionMutation.isPending}
        sites={sites}
      />

      {/* ─── Edit Gateway Dialog ──────────────────────────────── */}
      {editingGateway && (
        <EditGatewayDialog
          open={!!editingGateway}
          onOpenChange={(open) => { if (!open) setEditingGateway(null); }}
          gateway={editingGateway}
          onSubmit={(id, data) => updateGatewayMutation.mutate({ id, data })}
          onTestConnection={(id, overrides) => testExistingMutation.mutateAsync({ id, overrides })}
          isSubmitting={updateGatewayMutation.isPending}
          testResult={testExistingMutation.data?.data ?? null}
          isTesting={testExistingMutation.isPending}
          sites={sites}
        />
      )}

      {/* ─── Edit Rule Dialog ─────────────────────────────────── */}
      {editingRule && (
        <EditRuleDialog
          open={!!editingRule}
          onOpenChange={(open) => { if (!open) setEditingRule(null); }}
          rule={editingRule}
          onSubmit={(id, data) => updateRuleMutation.mutate({ id, data })}
          isSubmitting={updateRuleMutation.isPending}
        />
      )}
    </div>
  );
}
