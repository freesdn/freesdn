// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · VoIP Management Page
 *
 * Comprehensive Voice-over-IP dashboard with:
 *  - Dashboard overview with live stats, PBX status, queue status, recent calls
 *  - Phone/device management (Grandstream GDMS-style zero-touch provisioning)
 *  - PBX Systems (FreePBX, Asterisk, 3CX connections)
 *  - Extensions management
 *  - Ring Groups
 *  - Call Queues
 *  - Call History / CDR with filters
 *  - Voicemail inbox with play/download
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useMemo, useCallback } from 'react';
import { isValid } from 'date-fns';
import { useTranslation } from 'react-i18next';
import { useLocation, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import {
  Phone,
  PhoneCall,
  PhoneIncoming,
  PhoneOutgoing,
  PhoneMissed,
  PhoneOff,
  Settings,
  MoreHorizontal,
  CheckCircle,
  XCircle,
  AlertCircle,
  RefreshCw,
  Plus,
  Clock,
  Hash,
  Users,
  List,
  Route,
  Server,
  Voicemail,
  Download,
  Trash2,
  Play,
  BarChart3,
  Wifi,
  WifiOff,
  ChevronRight,
  Filter,
  ExternalLink,
  Globe,
  Shield,
  Cpu,
  HardDrive,
  Link2,
  Unlink,
  AlertTriangle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { SearchBar } from '@/components/ui/search-bar';
import { DataTable, DataTableColumn } from '@/components/ui/data-table';
import { Badge } from '@/components/ui/badge';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import { voipApi } from '@/lib/api';
import { cn } from '@/lib/utils';
import { EmptyState, NoResultsState } from '@/components/ui/empty-state';
import { StatsGrid } from '@/components/ui/stats-grid';
import { PageHeader } from '@/components/layout';
import { useToast } from '@/hooks/use-toast';

// =============================================================================
// Types
// =============================================================================

interface VoIPPhone {
  id: string;
  name: string;
  model?: string;
  vendor?: string;
  mac_address?: string;
  ip_address?: string;
  firmware_version?: string;
  serial_number?: string;
  extension_id?: string;
  location?: string;
  description?: string;
  status: 'online' | 'offline' | 'in_call' | 'ringing' | 'dnd' | 'unknown';
  last_seen?: string;
  settings?: Record<string, unknown>;
}

interface PBXSystem {
  id: string;
  name: string;
  description?: string;
  pbx_type: 'asterisk' | 'freepbx' | 'freeswitch' | '3cx' | 'other';
  ip_address?: string;
  api_port?: number;
  sip_port?: number;
  is_active: boolean;
  last_seen?: string;
  settings?: Record<string, unknown>;
}

interface Extension {
  id: string;
  pbx_id?: string;
  extension_number: string;
  display_name?: string;
  caller_id_name?: string;
  caller_id_number?: string;
  voicemail_enabled?: boolean;
  is_active: boolean;
  settings?: Record<string, unknown>;
}

interface RingGroup {
  id: string;
  pbx_id?: string;
  name: string;
  description?: string;
  group_number: string;
  ring_strategy: 'ringall' | 'hunt' | 'memoryhunt' | 'random';
  ring_time: number;
  members: string[];
  is_active: boolean;
}

interface CallLog {
  id: string;
  caller_number: string;
  caller_name?: string;
  callee_number: string;
  callee_name?: string;
  direction: 'inbound' | 'outbound' | 'internal';
  status: 'answered' | 'missed' | 'voicemail' | 'failed';
  duration_seconds: number;
  ring_duration_seconds?: number;
  start_time: string;
  answer_time?: string;
  end_time?: string;
  recording_path?: string;
}

interface PhoneStats {
  total: number;
  online: number;
  offline: number;
  in_call: number;
}

// Static data for features not yet backed by API
interface CallQueue {
  id: number;
  queue_number: string;
  name: string;
  strategy: string;
  current_callers: number;
  available_agents: number;
  calls_waiting: number;
}

interface SIPTrunk {
  id: number;
  name: string;
  provider?: string;
  host: string;
  is_registered: boolean;
  active_channels: number;
  max_channels: number;
}

interface VoicemailMessage {
  id: string;
  pbx_id?: string;
  extension_id?: string;
  extension_number: string;
  caller_id: string;
  caller_name?: string;
  duration: number;
  message_date: string;
  is_read: boolean;
  is_urgent: boolean;
  transcription?: string;
  file_path?: string;
  folder?: string;
}

// =============================================================================
// (queues & trunks fetched from real API per PBX below)
// =============================================================================

// =============================================================================
// Sub-Components
// =============================================================================

/** Phone status badge */
function PhoneStatusBadge({ status }: { status: VoIPPhone['status'] }) {
  const { t } = useTranslation('voip');
  const config: Record<string, { icon: typeof CheckCircle; label: string; className: string }> = {
    online: { icon: CheckCircle, label: t('VoIPPage.phoneStatus.online'), className: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' },
    offline: { icon: XCircle, label: t('VoIPPage.phoneStatus.offline'), className: 'bg-red-500/10 text-red-500 border-red-500/20' },
    in_call: { icon: PhoneCall, label: t('VoIPPage.phoneStatus.inCall'), className: 'bg-amber-500/10 text-amber-500 border-amber-500/20' },
    ringing: { icon: PhoneIncoming, label: t('VoIPPage.phoneStatus.ringing'), className: 'bg-blue-500/10 text-blue-500 border-blue-500/20 animate-pulse' },
    dnd: { icon: PhoneOff, label: t('VoIPPage.phoneStatus.dnd'), className: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20' },
    unknown: { icon: AlertCircle, label: t('VoIPPage.phoneStatus.unknown'), className: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20' },
  };
  const { icon: Icon, label, className } = config[status] || config.unknown;
  return (
    <Badge variant="outline" className={cn('gap-1', className)}>
      <Icon className="h-3 w-3" />
      {label}
    </Badge>
  );
}

/** Call direction badge */
function CallDirectionBadge({ direction }: { direction: CallLog['direction'] }) {
  const { t } = useTranslation('voip');
  const config = {
    inbound: { icon: PhoneIncoming, label: t('VoIPPage.callDirection.inbound'), className: 'text-blue-500' },
    outbound: { icon: PhoneOutgoing, label: t('VoIPPage.callDirection.outbound'), className: 'text-emerald-500' },
    internal: { icon: Phone, label: t('VoIPPage.callDirection.internal'), className: 'text-muted-foreground' },
  };
  const { icon: Icon, label, className } = config[direction] || config.internal;
  return (
    <div className={cn('flex items-center gap-1', className)}>
      <Icon className="h-4 w-4" />
      <span className="text-sm">{label}</span>
    </div>
  );
}

/** PBX type badge */
function PBXTypeBadge({ type }: { type: PBXSystem['pbx_type'] }) {
  const { t } = useTranslation('voip');
  const config: Record<string, { label: string; className: string }> = {
    freepbx: { label: 'FreePBX', className: 'bg-orange-500/10 text-orange-500 border-orange-500/20' },
    asterisk: { label: 'Asterisk', className: 'bg-blue-500/10 text-blue-500 border-blue-500/20' },
    freeswitch: { label: 'FreeSWITCH', className: 'bg-cyan-500/10 text-cyan-500 border-cyan-500/20' },
    '3cx': { label: '3CX', className: 'bg-green-500/10 text-green-500 border-green-500/20' },
    other: { label: t('VoIPPage.pbxType.other'), className: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20' },
  };
  const { label, className } = config[type] || config.other;
  return <Badge variant="outline" className={cn('gap-1', className)}>{label}</Badge>;
}

/** Ring strategy badge */
function StrategyBadge({ strategy }: { strategy: RingGroup['ring_strategy'] }) {
  const { t } = useTranslation('voip');
  const labels: Record<string, string> = {
    ringall: t('VoIPPage.ringStrategy.ringall'),
    hunt: t('VoIPPage.ringStrategy.hunt'),
    memoryhunt: t('VoIPPage.ringStrategy.memoryhunt'),
    random: t('VoIPPage.ringStrategy.random'),
  };
  return (
    <Badge variant="outline" className="bg-purple-500/10 text-purple-500 border-purple-500/20">
      {labels[strategy] || strategy}
    </Badge>
  );
}

/** Format seconds → human duration */
function formatDuration(seconds: number): string {
  if (!seconds || seconds <= 0) return '0s';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

/** Format time-ago string from ISO date */
function timeAgo(dateStr?: string): string {
  if (!dateStr) return 'Never';
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

// =============================================================================
// Phone Device Card (Grandstream GDMS-style)
// =============================================================================

function PhoneDeviceCard({ phone }: { phone: VoIPPhone }) {
  const { t } = useTranslation('voip');
  const isOnline = phone.status === 'online' || phone.status === 'in_call' || phone.status === 'ringing';
  return (
    <Card className="hover:shadow-md transition-shadow cursor-pointer">
      <CardContent noOffset className="pb-4">
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className={cn('p-3 rounded-lg', isOnline ? 'bg-emerald-500/10' : 'bg-muted')}>
              <Phone className={cn('h-6 w-6', isOnline ? 'text-emerald-500' : 'text-muted-foreground')} />
            </div>
            <div>
              <p className="font-medium leading-tight">{phone.name}</p>
              <p className="text-sm text-muted-foreground">
                {phone.vendor ? `${phone.vendor} ${phone.model || ''}`.trim() : phone.model || t('VoIPPage.phoneCard.unknownDevice')}
              </p>
            </div>
          </div>
          <PhoneStatusBadge status={phone.status} />
        </div>

        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-sm">
          <div className="flex items-center gap-1.5">
            <Hash className="h-3 w-3 text-muted-foreground flex-shrink-0" />
            <span className="text-muted-foreground">{t('VoIPPage.phoneCard.extLabel')}</span>
            <span className="font-mono font-medium">{phone.extension_id || '-'}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <Globe className="h-3 w-3 text-muted-foreground flex-shrink-0" />
            <span className="text-muted-foreground">{t('VoIPPage.phoneCard.ipLabel')}</span>
            <span className="font-mono text-xs">{phone.ip_address || '-'}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <Cpu className="h-3 w-3 text-muted-foreground flex-shrink-0" />
            <span className="text-muted-foreground">{t('VoIPPage.phoneCard.macLabel')}</span>
            <span className="font-mono text-xs">{phone.mac_address || '-'}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <HardDrive className="h-3 w-3 text-muted-foreground flex-shrink-0" />
            <span className="text-muted-foreground">{t('VoIPPage.phoneCard.fwLabel')}</span>
            <span className="text-xs">{phone.firmware_version || '-'}</span>
          </div>
        </div>

        {phone.last_seen && (
          <p className="text-xs text-muted-foreground mt-2">
            {t('VoIPPage.phoneCard.lastSeen', { time: timeAgo(phone.last_seen) })}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// =============================================================================
// Add PBX Dialog
// =============================================================================

interface AddPBXDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (data: any) => void;
  onTestConnection: (data: any) => Promise<any>;
  isSubmitting: boolean;
  testResult: any | null;
  isTesting: boolean;
}

// Only PBX types with a real, shipping adapter are offered. FreePBX is the only
// implemented adapter; Asterisk / FreeSWITCH / 3CX have no backend and would fail
// on connect, so they are NOT listed (matches PBXPage.tsx + app/adapters/maturity.py).
const PBX_TYPE_OPTIONS = [
  { value: 'freepbx', label: 'FreePBX', description: 'FreePBX / Asterisk AMI', defaultPort: 443 },
] as const;

function AddPBXDialog({
  open,
  onOpenChange,
  onSubmit,
  onTestConnection,
  isSubmitting,
  testResult,
  isTesting,
}: AddPBXDialogProps) {
  const { t } = useTranslation('voip');
  const [form, setForm] = useState({
    name: '',
    pbx_type: 'freepbx',
    ip_address: '',
    api_port: 443,
    sip_port: 5060,
    description: '',
    api_username: '',
    api_password: '',
    api_key: '',
  });

  const updateField = (field: string, value: string | number) =>
    setForm((prev) => ({ ...prev, [field]: value }));

  const handleTypeChange = (type: string) => {
    const option = PBX_TYPE_OPTIONS.find((o) => o.value === type);
    setForm((prev) => ({ ...prev, pbx_type: type, api_port: option?.defaultPort ?? 443 }));
  };

  const handleTest = () => {
    onTestConnection({
      pbx_type: form.pbx_type,
      ip_address: form.ip_address,
      api_port: form.api_port,
      api_username: form.api_username || undefined,
      api_password: form.api_password || undefined,
      api_key: form.api_key || undefined,
    });
  };

  const handleSubmit = () => {
    onSubmit({
      name: form.name,
      pbx_type: form.pbx_type,
      ip_address: form.ip_address,
      api_port: form.api_port,
      sip_port: form.sip_port,
      description: form.description || undefined,
      api_username: form.api_username || undefined,
      api_password: form.api_password || undefined,
      api_key: form.api_key || undefined,
      is_active: true,
    });
  };

  const canSubmit = form.name.trim() && form.ip_address.trim();

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[560px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            {t('VoIPPage.addPbxDialog.title')}
          </DialogTitle>
          <DialogDescription>
            {t('VoIPPage.addPbxDialog.description')}
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 py-2">
          {/* PBX Type */}
          <div className="grid gap-2">
            <Label htmlFor="pbx_type">{t('VoIPPage.addPbxDialog.pbxTypeLabel')}</Label>
            <Select value={form.pbx_type} onValueChange={handleTypeChange}>
              <SelectTrigger>
                <SelectValue placeholder={t('VoIPPage.addPbxDialog.pbxTypePlaceholder')} />
              </SelectTrigger>
              <SelectContent>
                {PBX_TYPE_OPTIONS.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{opt.label}</span>
                      <span className="text-muted-foreground text-xs">- {t(`VoIPPage.pbxTypeOptions.${opt.value}`)}</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Name */}
          <div className="grid gap-2">
            <Label htmlFor="name">{t('VoIPPage.addPbxDialog.displayNameLabel')}</Label>
            <Input
              id="name"
              placeholder={t('VoIPPage.addPbxDialog.displayNamePlaceholder')}
              value={form.name}
              onChange={(e) => updateField('name', e.target.value)}
            />
          </div>

          {/* Connection */}
          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-2">
              <Label htmlFor="ip_address">{t('VoIPPage.addPbxDialog.ipAddressLabel')}</Label>
              <Input
                id="ip_address"
                placeholder="192.168.1.100"
                value={form.ip_address}
                onChange={(e) => updateField('ip_address', e.target.value)}
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="grid gap-2">
                <Label htmlFor="api_port">{t('VoIPPage.addPbxDialog.apiPortLabel')}</Label>
                <Input
                  id="api_port"
                  type="number"
                  value={form.api_port}
                  onChange={(e) => updateField('api_port', parseInt(e.target.value) || 443)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="sip_port">{t('VoIPPage.addPbxDialog.sipPortLabel')}</Label>
                <Input
                  id="sip_port"
                  type="number"
                  value={form.sip_port}
                  onChange={(e) => updateField('sip_port', parseInt(e.target.value) || 5060)}
                />
              </div>
            </div>
          </div>

          {/* Credentials */}
          <div className="grid gap-2">
            <Label className="text-muted-foreground text-xs uppercase tracking-wide">{t('VoIPPage.addPbxDialog.credentialsLabel')}</Label>
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="api_username">{t('VoIPPage.addPbxDialog.usernameLabel')}</Label>
                <Input
                  id="api_username"
                  placeholder="admin"
                  value={form.api_username}
                  onChange={(e) => updateField('api_username', e.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="api_password">{t('VoIPPage.addPbxDialog.passwordLabel')}</Label>
                <Input
                  id="api_password"
                  type="password"
                  placeholder="••••••••"
                  value={form.api_password}
                  onChange={(e) => updateField('api_password', e.target.value)}
                />
              </div>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="api_key">{t('VoIPPage.addPbxDialog.apiKeyLabel')}</Label>
              <Input
                id="api_key"
                placeholder={t('VoIPPage.addPbxDialog.apiKeyPlaceholder')}
                value={form.api_key}
                onChange={(e) => updateField('api_key', e.target.value)}
              />
            </div>
          </div>

          {/* Description */}
          <div className="grid gap-2">
            <Label htmlFor="description">{t('VoIPPage.addPbxDialog.descriptionLabel')}</Label>
            <Input
              id="description"
              placeholder={t('VoIPPage.addPbxDialog.descriptionPlaceholder')}
              value={form.description}
              onChange={(e) => updateField('description', e.target.value)}
            />
          </div>

          {/* Test Connection */}
          {testResult && (
            <Card className={cn(
              'border',
              testResult.status === 'success'
                ? 'border-emerald-500/30 bg-emerald-500/5'
                : 'border-red-500/30 bg-red-500/5',
            )}>
              <CardContent noOffset className="py-3 flex items-center gap-3">
                {testResult.status === 'success' ? (
                  <CheckCircle className="h-5 w-5 text-emerald-500 flex-shrink-0" />
                ) : (
                  <XCircle className="h-5 w-5 text-red-500 flex-shrink-0" />
                )}
                <div>
                  <p className="text-sm font-medium">{testResult.message}</p>
                  {testResult.response_time_ms && (
                    <p className="text-xs text-muted-foreground">
                      {t('VoIPPage.addPbxDialog.responseTime', { ms: testResult.response_time_ms })}
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        <DialogFooter className="gap-2 sm:gap-0">
          <Button
            variant="outline"
            onClick={handleTest}
            disabled={!form.ip_address.trim() || isTesting}
          >
            {isTesting ? (
              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Link2 className="h-4 w-4 mr-2" />
            )}
            {t('VoIPPage.addPbxDialog.testConnection')}
          </Button>
          <Button onClick={handleSubmit} disabled={!canSubmit || isSubmitting}>
            {isSubmitting ? (
              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Plus className="h-4 w-4 mr-2" />
            )}
            {t('VoIPPage.addPbxDialog.addPbx')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// =============================================================================
// Add Phone Dialog
// =============================================================================

interface AddPhoneDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (data: any) => void;
  isSubmitting: boolean;
  pbxSystems: PBXSystem[];
}

function AddPhoneDialog({ open, onOpenChange, onSubmit, isSubmitting, pbxSystems }: AddPhoneDialogProps) {
  const { t } = useTranslation('voip');
  const [form, setForm] = useState({
    name: '',
    vendor: '',
    model: '',
    mac_address: '',
    ip_address: '',
    serial_number: '',
    location: '',
    description: '',
    pbx_id: '',
  });

  const updateField = (field: string, value: string) =>
    setForm((prev) => ({ ...prev, [field]: value }));

  const handleSubmit = () => {
    onSubmit({
      name: form.name,
      vendor: form.vendor || undefined,
      model: form.model || undefined,
      mac_address: form.mac_address || undefined,
      ip_address: form.ip_address || undefined,
      serial_number: form.serial_number || undefined,
      location: form.location || undefined,
      description: form.description || undefined,
      pbx_id: form.pbx_id || undefined,
      status: 'offline',
    });
  };

  const canSubmit = form.name.trim();

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[520px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Phone className="h-5 w-5" />
            {t('VoIPPage.addPhoneDialog.title')}
          </DialogTitle>
          <DialogDescription>
            {t('VoIPPage.addPhoneDialog.description')}
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 py-2">
          {/* Name */}
          <div className="grid gap-2">
            <Label htmlFor="phone_name">{t('VoIPPage.addPhoneDialog.phoneNameLabel')}</Label>
            <Input
              id="phone_name"
              placeholder={t('VoIPPage.addPhoneDialog.phoneNamePlaceholder')}
              value={form.name}
              onChange={(e) => updateField('name', e.target.value)}
            />
          </div>

          {/* Vendor + Model */}
          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-2">
              <Label htmlFor="vendor">{t('VoIPPage.addPhoneDialog.vendorLabel')}</Label>
              <Select value={form.vendor} onValueChange={(v) => updateField('vendor', v)}>
                <SelectTrigger>
                  <SelectValue placeholder={t('VoIPPage.addPhoneDialog.vendorPlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="Grandstream">Grandstream</SelectItem>
                  <SelectItem value="Yealink">Yealink</SelectItem>
                  <SelectItem value="Polycom">Polycom</SelectItem>
                  <SelectItem value="Cisco">Cisco</SelectItem>
                  <SelectItem value="Fanvil">Fanvil</SelectItem>
                  <SelectItem value="Snom">Snom</SelectItem>
                  <SelectItem value="Other">{t('VoIPPage.addPhoneDialog.vendorOther')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="phone_model">{t('VoIPPage.addPhoneDialog.modelLabel')}</Label>
              <Input
                id="phone_model"
                placeholder={t('VoIPPage.addPhoneDialog.modelPlaceholder')}
                value={form.model}
                onChange={(e) => updateField('model', e.target.value)}
              />
            </div>
          </div>

          {/* Network */}
          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-2">
              <Label htmlFor="phone_mac">{t('VoIPPage.addPhoneDialog.macLabel')}</Label>
              <Input
                id="phone_mac"
                placeholder="00:0B:82:XX:XX:XX"
                value={form.mac_address}
                onChange={(e) => updateField('mac_address', e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="phone_ip">{t('VoIPPage.addPhoneDialog.ipLabel')}</Label>
              <Input
                id="phone_ip"
                placeholder="e.g. 192.168.1.150"
                value={form.ip_address}
                onChange={(e) => updateField('ip_address', e.target.value)}
              />
            </div>
          </div>

          {/* PBX Assignment */}
          {pbxSystems.length > 0 && (
            <div className="grid gap-2">
              <Label htmlFor="phone_pbx">{t('VoIPPage.addPhoneDialog.assignPbxLabel')}</Label>
              <Select value={form.pbx_id} onValueChange={(v) => updateField('pbx_id', v)}>
                <SelectTrigger>
                  <SelectValue placeholder={t('VoIPPage.addPhoneDialog.assignPbxPlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  {pbxSystems.map((p) => (
                    <SelectItem key={p.id} value={p.id}>
                      {p.name} ({p.pbx_type?.toUpperCase() ?? '-'})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          {/* Serial + Location */}
          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-2">
              <Label htmlFor="phone_serial">{t('VoIPPage.addPhoneDialog.serialLabel')}</Label>
              <Input
                id="phone_serial"
                placeholder={t('VoIPPage.addPhoneDialog.serialPlaceholder')}
                value={form.serial_number}
                onChange={(e) => updateField('serial_number', e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="phone_location">{t('VoIPPage.addPhoneDialog.locationLabel')}</Label>
              <Input
                id="phone_location"
                placeholder={t('VoIPPage.addPhoneDialog.locationPlaceholder')}
                value={form.location}
                onChange={(e) => updateField('location', e.target.value)}
              />
            </div>
          </div>

          {/* Description */}
          <div className="grid gap-2">
            <Label htmlFor="phone_desc">{t('VoIPPage.addPhoneDialog.descriptionLabel')}</Label>
            <Input
              id="phone_desc"
              placeholder={t('VoIPPage.addPhoneDialog.descriptionPlaceholder')}
              value={form.description}
              onChange={(e) => updateField('description', e.target.value)}
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('VoIPPage.addPhoneDialog.cancel')}</Button>
          <Button onClick={handleSubmit} disabled={!canSubmit || isSubmitting}>
            {isSubmitting ? (
              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Plus className="h-4 w-4 mr-2" />
            )}
            {t('VoIPPage.addPhoneDialog.addPhone')}
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
  dashboard: '/voip',
  phones: '/voip/phones',
  pbx: '/voip/pbx',
  extensions: '/voip/extensions',
  ringgroups: '/voip/ring-groups',
  queues: '/voip/queues',
  calls: '/voip/calls',
  voicemail: '/voip/voicemail',
};

const PATH_TO_TAB: Record<string, string> = Object.fromEntries(
  Object.entries(TAB_PATHS).map(([tab, path]) => [path, tab]),
);

function resolveTabFromPath(pathname: string): string {
  // Exact match first, then try stripping trailing slash
  if (PATH_TO_TAB[pathname]) return PATH_TO_TAB[pathname];
  const clean = pathname.replace(/\/$/, '');
  if (PATH_TO_TAB[clean]) return PATH_TO_TAB[clean];
  return 'dashboard';
}

// =============================================================================
// Main Page
// =============================================================================

export default function VoIPPage() {
  const { t } = useTranslation('voip');
  const { toast } = useToast();
  const location = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchQuery, setSearchQuery] = useState('');
  const [phoneView, setPhoneView] = useState<'grid' | 'table'>('grid');
  const [showAddPBX, setShowAddPBX] = useState(false);
  const [showAddPhone, setShowAddPhone] = useState(false);

  // Ring-group create dialog
  const emptyRgForm = {
    pbx_id: '',
    group_number: '',
    name: '',
    ring_strategy: 'ringall',
    ring_time: 20,
    members: '',
  };
  const [showAddRingGroup, setShowAddRingGroup] = useState(false);
  const [rgForm, setRgForm] = useState(emptyRgForm);

  // Derive active tab from URL
  const activeTab = resolveTabFromPath(location.pathname);

  const handleTabChange = useCallback(
    (tab: string) => {
      setSearchQuery('');
      navigate(TAB_PATHS[tab] || '/voip');
    },
    [navigate],
  );

  // Site context
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ─────────────────────────────────────────────────────────────────
  // API Queries
  // ─────────────────────────────────────────────────────────────────

  const { data: phonesRes, isLoading: phonesLoading, isError: phonesError, refetch: refetchPhones } = useQuery({
    queryKey: ['voip-phones', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getPhones({ limit: 200, ...(selectedSiteId ? { site_id: selectedSiteId } : {}) }),
    refetchInterval: 30_000,
    staleTime: 10_000,
  });

  const { data: statsRes, isError: statsError } = useQuery({
    queryKey: ['voip-phone-stats', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getPhoneStats(selectedSiteId ?? undefined),
    refetchInterval: 15_000,
  });

  const { data: pbxRes, isLoading: pbxLoading, isError: pbxError, refetch: refetchPBX } = useQuery({
    queryKey: ['voip-pbx', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getPBXSystems({ limit: 50, ...(selectedSiteId ? { site_id: selectedSiteId } : {}) }),
  });

  const { data: extensionsRes, isLoading: extensionsLoading, isError: extensionsError } = useQuery({
    queryKey: ['voip-all-extensions', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getAllExtensions({ limit: 500, ...(selectedSiteId ? { site_id: selectedSiteId } : {}) }),
  });

  const { data: ringGroupsRes, isLoading: ringGroupsLoading, isError: ringGroupsError } = useQuery({
    queryKey: ['voip-ring-groups', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getRingGroups({ limit: 200, ...(selectedSiteId ? { site_id: selectedSiteId } : {}) }),
  });

  const { data: callLogsRes, isLoading: logsLoading, isError: logsError, refetch: refetchLogs } = useQuery({
    queryKey: ['voip-call-logs', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getCallLogs({ limit: 50, ...(selectedSiteId ? { site_id: selectedSiteId } : {}) }),
  });

  const { data: _callStatsRes } = useQuery({
    queryKey: ['voip-call-stats', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getCallStats({ ...(selectedSiteId ? { site_id: selectedSiteId } : {}) }),
  });

  const { data: voicemailsRes, isLoading: voicemailsLoading, isError: voicemailsError, refetch: refetchVoicemails } = useQuery({
    queryKey: ['voip-voicemails', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getVoicemails({ limit: 200, ...(selectedSiteId ? { site_id: selectedSiteId } : {}) }),
    refetchInterval: 30_000,
    staleTime: 10_000,
  });

  const { data: voicemailStatsRes } = useQuery({
    queryKey: ['voip-voicemail-stats', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getVoicemailStats({ ...(selectedSiteId ? { site_id: selectedSiteId } : {}) }),
    refetchInterval: 30_000,
  });

  // Derive PBX IDs early so we can aggregate queues & trunks across all PBX systems
  const pbxIds = useMemo(() => {
    const items = pbxRes?.data?.items ?? pbxRes?.data ?? [];
    return (items as PBXSystem[]).map((p) => p.id);
  }, [pbxRes?.data]);

  const { data: queuesData } = useQuery({
    queryKey: ['voip-all-queues', pbxIds, { siteId: selectedSiteId }],
    queryFn: async () => {
      const results = await Promise.all(pbxIds.map((id) => voipApi.getPBXQueues(id)));
      return results.flatMap((r) => r.data?.items ?? r.data ?? []);
    },
    enabled: pbxIds.length > 0,
    refetchInterval: 30_000,
    staleTime: 10_000,
  });

  const { data: trunksData } = useQuery({
    queryKey: ['voip-all-trunks', pbxIds, { siteId: selectedSiteId }],
    queryFn: async () => {
      const results = await Promise.all(pbxIds.map((id) => voipApi.getPBXTrunks(id)));
      return results.flatMap((r) => r.data?.items ?? r.data ?? []);
    },
    enabled: pbxIds.length > 0,
    refetchInterval: 30_000,
    staleTime: 10_000,
  });

  // ─────────────────────────────────────────────────────────────────
  // PBX Mutations
  // ─────────────────────────────────────────────────────────────────

  const createPBXMutation = useMutation({
    mutationFn: (data: any) => voipApi.createPBX(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['voip-pbx'] });
      setShowAddPBX(false);
    },
    onError: (err: any) => toast({ title: t('VoIPPage.toasts.createPbxFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  const deletePBXMutation = useMutation({
    mutationFn: (id: string) => voipApi.deletePBX(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['voip-pbx'] });
    },
    onError: (err: any) => toast({ title: t('VoIPPage.toasts.deletePbxFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  // ─────────────────────────────────────────────────────────────────
  // Ring-group Mutations (POST/DELETE /voip/ring-groups)
  // ─────────────────────────────────────────────────────────────────

  const createRingGroupMutation = useMutation({
    mutationFn: () => {
      const members = rgForm.members.split(',').map((m) => m.trim()).filter(Boolean);
      return voipApi.createRingGroup({
        pbx_id: rgForm.pbx_id,
        group_number: rgForm.group_number,
        name: rgForm.name,
        ring_strategy: rgForm.ring_strategy,
        ring_time: Number(rgForm.ring_time) || 20,
        members,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['voip-ring-groups'] });
      setShowAddRingGroup(false);
      setRgForm(emptyRgForm);
    },
    onError: (err: any) => toast({ title: t('VoIPPage.ringGroupsTab.addRingGroup'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  const deleteRingGroupMutation = useMutation({
    mutationFn: (id: string) => voipApi.deleteRingGroup(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['voip-ring-groups'] });
    },
    onError: (err: any) => toast({ title: t('common:delete'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  const syncPBXMutation = useMutation({
    mutationFn: (id: string) => voipApi.syncPBX(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['voip-pbx'] });
      queryClient.invalidateQueries({ queryKey: ['voip-all-extensions'] });
    },
    onError: (err: any) => toast({ title: t('VoIPPage.toasts.syncFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  const testConnectionMutation = useMutation({
    mutationFn: (data: {
      pbx_type: string;
      ip_address: string;
      api_port?: number;
      api_username?: string;
      api_password?: string;
      api_key?: string;
    }) => voipApi.testPBXConnection(data),
    onError: (err: any) => toast({ title: t('VoIPPage.toasts.connectionTestFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  // ─────────────────────────────────────────────────────────────────
  // Phone Mutations
  // ─────────────────────────────────────────────────────────────────

  const createPhoneMutation = useMutation({
    mutationFn: (data: any) => voipApi.createPhone(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['voip-phones'] });
      queryClient.invalidateQueries({ queryKey: ['voip-phone-stats'] });
      setShowAddPhone(false);
    },
    onError: (err: any) => toast({ title: t('VoIPPage.toasts.createPhoneFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  const deletePhoneMutation = useMutation({
    mutationFn: (id: string) => voipApi.deletePhone(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['voip-phones'] });
      queryClient.invalidateQueries({ queryKey: ['voip-phone-stats'] });
    },
    onError: (err: any) => toast({ title: t('VoIPPage.toasts.deletePhoneFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  // ─────────────────────────────────────────────────────────────────
  // Voicemail Mutations
  // ─────────────────────────────────────────────────────────────────

  const markVoicemailReadMutation = useMutation({
    mutationFn: (id: string) => voipApi.markVoicemailRead(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['voip-voicemails'] });
      queryClient.invalidateQueries({ queryKey: ['voip-voicemail-stats'] });
    },
    onError: (err: any) => toast({ title: t('VoIPPage.toasts.markReadFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  const deleteVoicemailMutation = useMutation({
    mutationFn: (id: string) => voipApi.deleteVoicemail(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['voip-voicemails'] });
      queryClient.invalidateQueries({ queryKey: ['voip-voicemail-stats'] });
    },
    onError: (err: any) => toast({ title: t('VoIPPage.toasts.deleteVoicemailFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  // ─────────────────────────────────────────────────────────────────
  // Derived data (safe unwrap from AxiosResponse)
  // ─────────────────────────────────────────────────────────────────

  const phones: VoIPPhone[] = useMemo(() => phonesRes?.data?.items ?? phonesRes?.data ?? [], [phonesRes?.data]);
  const pbxSystems: PBXSystem[] = pbxRes?.data?.items ?? pbxRes?.data ?? [];
  const extensions: Extension[] = useMemo(() => extensionsRes?.data?.items ?? extensionsRes?.data ?? [], [extensionsRes?.data]);
  const ringGroups: RingGroup[] = ringGroupsRes?.data?.items ?? ringGroupsRes?.data ?? [];
  const callLogs: CallLog[] = useMemo(
    () => callLogsRes?.data?.items ?? callLogsRes?.data ?? [],
    [callLogsRes],
  );

  // Phone stats · prefer server, fall back to local count
  const stats: PhoneStats = statsRes?.data ?? {
    total: phones.length,
    online: phones.filter((p) => p.status === 'online').length,
    offline: phones.filter((p) => p.status === 'offline').length,
    in_call: phones.filter((p) => p.status === 'in_call').length,
  };

  const queues: CallQueue[] = queuesData ?? [];
  const trunks: SIPTrunk[] = trunksData ?? [];
  const voicemails: VoicemailMessage[] = voicemailsRes?.data?.items ?? voicemailsRes?.data ?? [];
  const voicemailStats = voicemailStatsRes?.data ?? { total: voicemails.length, unread: voicemails.filter((v) => !v.is_read).length, urgent: 0 };

  const unreadVoicemails = voicemailStats.unread;

  // ─────────────────────────────────────────────────────────────────
  // Filtered data
  // ─────────────────────────────────────────────────────────────────

  const filteredPhones = useMemo(
    () =>
      phones.filter(
        (p) =>
          p.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
          p.extension_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
          p.ip_address?.toLowerCase().includes(searchQuery.toLowerCase()) ||
          p.mac_address?.toLowerCase().includes(searchQuery.toLowerCase()) ||
          p.vendor?.toLowerCase().includes(searchQuery.toLowerCase()) ||
          p.model?.toLowerCase().includes(searchQuery.toLowerCase()),
      ),
    [phones, searchQuery],
  );

  const filteredExtensions = useMemo(
    () =>
      extensions.filter(
        (e) =>
          e.extension_number?.toLowerCase().includes(searchQuery.toLowerCase()) ||
          e.display_name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
          e.caller_id_name?.toLowerCase().includes(searchQuery.toLowerCase()),
      ),
    [extensions, searchQuery],
  );

  // ─────────────────────────────────────────────────────────────────
  // CSV export · serialize the loaded call-log rows client-side
  // ─────────────────────────────────────────────────────────────────

  const exportCallLogsCsv = useCallback(() => {
    if (callLogs.length === 0) return;
    const headers = ['direction', 'from', 'to', 'status', 'duration_seconds', 'start_time'];
    const escape = (v: unknown) => {
      const s = v == null ? '' : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const rows = callLogs.map((log) => [
      log.direction,
      log.caller_name || log.caller_number,
      log.callee_name || log.callee_number,
      log.status,
      log.duration_seconds,
      log.start_time,
    ].map(escape).join(','));
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `call-logs-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [callLogs]);

  // ─────────────────────────────────────────────────────────────────
  // Column Definitions
  // ─────────────────────────────────────────────────────────────────

  const phoneColumns: DataTableColumn<VoIPPhone>[] = [
    {
      id: 'name',
      header: t('VoIPPage.phoneColumns.phone'),
      cell: (phone) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-muted">
            <Phone className="h-4 w-4 text-muted-foreground" />
          </div>
          <div>
            <div className="font-medium">{phone.name}</div>
            <div className="text-sm text-muted-foreground">
              {phone.vendor ? `${phone.vendor} ${phone.model || ''}`.trim() : phone.model || t('VoIPPage.common.unknown')}
            </div>
          </div>
        </div>
      ),
    },
    {
      id: 'extension',
      header: t('VoIPPage.phoneColumns.extension'),
      cell: (phone) => (
        <div className="flex items-center gap-1">
          <Hash className="h-3 w-3 text-muted-foreground" />
          <span className="font-mono">{phone.extension_id || '-'}</span>
        </div>
      ),
    },
    {
      id: 'ip_address',
      header: t('VoIPPage.phoneColumns.ipAddress'),
      cell: (phone) => <code className="text-sm">{phone.ip_address || '-'}</code>,
    },
    {
      id: 'mac_address',
      header: t('VoIPPage.phoneColumns.macAddress'),
      cell: (phone) => <code className="text-xs text-muted-foreground">{phone.mac_address || '-'}</code>,
    },
    {
      id: 'firmware',
      header: t('VoIPPage.phoneColumns.firmware'),
      cell: (phone) => <span className="text-sm text-muted-foreground">{phone.firmware_version || '-'}</span>,
    },
    {
      id: 'status',
      header: t('VoIPPage.phoneColumns.status'),
      cell: (phone) => <PhoneStatusBadge status={phone.status} />,
    },
    {
      id: 'last_seen',
      header: t('VoIPPage.phoneColumns.lastSeen'),
      cell: (phone) => <span className="text-sm text-muted-foreground">{timeAgo(phone.last_seen)}</span>,
    },
    {
      id: 'actions',
      header: '',
      cell: (phone) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon"><MoreHorizontal className="h-4 w-4" /></Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem><Phone className="h-4 w-4 mr-2" />{t('VoIPPage.phoneActions.viewDetails')}</DropdownMenuItem>
            <DropdownMenuItem><PhoneCall className="h-4 w-4 mr-2" />{t('VoIPPage.phoneActions.callLogs')}</DropdownMenuItem>
            <DropdownMenuItem><RefreshCw className="h-4 w-4 mr-2" />{t('VoIPPage.phoneActions.rebootPhone')}</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem><Settings className="h-4 w-4 mr-2" />{t('VoIPPage.phoneActions.provisionConfig')}</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="text-red-500 focus:text-red-500"
              onClick={() => {
                if (window.confirm(t('VoIPPage.confirm.deletePhone', { name: phone.name }))) {
                  deletePhoneMutation.mutate(phone.id);
                }
              }}
            >
              <Trash2 className="h-4 w-4 mr-2" />{t('VoIPPage.phoneActions.deletePhone')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ];

  const pbxColumns: DataTableColumn<PBXSystem>[] = [
    {
      id: 'name',
      header: t('VoIPPage.pbxColumns.pbxSystem'),
      cell: (pbx) => (
        <div className="flex items-center gap-3">
          <div className={cn('p-2 rounded-lg', pbx.is_active ? 'bg-emerald-500/10' : 'bg-muted')}>
            <Server className={cn('h-4 w-4', pbx.is_active ? 'text-emerald-500' : 'text-muted-foreground')} />
          </div>
          <div>
            <div className="font-medium">{pbx.name}</div>
            {pbx.description && <div className="text-sm text-muted-foreground">{pbx.description}</div>}
          </div>
        </div>
      ),
    },
    {
      id: 'type',
      header: t('VoIPPage.pbxColumns.type'),
      cell: (pbx) => <PBXTypeBadge type={pbx.pbx_type} />,
    },
    {
      id: 'ip',
      header: t('VoIPPage.pbxColumns.address'),
      cell: (pbx) => (
        <div>
          <code className="text-sm">{pbx.ip_address || '-'}</code>
          {pbx.sip_port && <span className="text-xs text-muted-foreground ml-1">:{pbx.sip_port}</span>}
        </div>
      ),
    },
    {
      id: 'status',
      header: t('VoIPPage.pbxColumns.status'),
      cell: (pbx) => (
        <Badge variant="outline" className={cn('gap-1', pbx.is_active ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' : 'bg-red-500/10 text-red-500 border-red-500/20')}>
          {pbx.is_active ? <Link2 className="h-3 w-3" /> : <Unlink className="h-3 w-3" />}
          {pbx.is_active ? t('VoIPPage.pbxStatus.connected') : t('VoIPPage.pbxStatus.disconnected')}
        </Badge>
      ),
    },
    {
      id: 'last_seen',
      header: t('VoIPPage.pbxColumns.lastSeen'),
      cell: (pbx) => <span className="text-sm text-muted-foreground">{timeAgo(pbx.last_seen)}</span>,
    },
    {
      id: 'actions',
      header: '',
      cell: (pbx) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon"><MoreHorizontal className="h-4 w-4" /></Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem><Settings className="h-4 w-4 mr-2" />{t('VoIPPage.pbxActions.configure')}</DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => window.open(`https://${pbx.ip_address}:${pbx.api_port || 443}`, '_blank', 'noopener,noreferrer')}
            >
              <ExternalLink className="h-4 w-4 mr-2" />{t('VoIPPage.pbxActions.openAdminUi')}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => syncPBXMutation.mutate(pbx.id)}>
              <RefreshCw className="h-4 w-4 mr-2" />{t('VoIPPage.pbxActions.syncExtensions')}
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="text-red-500 focus:text-red-500"
              onClick={() => {
                if (confirm(t('VoIPPage.confirm.deletePbx', { name: pbx.name }))) {
                  deletePBXMutation.mutate(pbx.id);
                }
              }}
            >
              <Trash2 className="h-4 w-4 mr-2" />{t('VoIPPage.pbxActions.delete')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ];

  const extensionColumns: DataTableColumn<Extension>[] = [
    {
      id: 'extension_number',
      header: t('VoIPPage.extensionColumns.extension'),
      cell: (ext) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-muted">
            <Hash className="h-4 w-4 text-muted-foreground" />
          </div>
          <span className="font-mono font-medium">{ext.extension_number}</span>
        </div>
      ),
    },
    {
      id: 'display_name',
      header: t('VoIPPage.extensionColumns.displayName'),
      cell: (ext) => ext.display_name || '-',
    },
    {
      id: 'caller_id',
      header: t('VoIPPage.extensionColumns.callerId'),
      cell: (ext) => (
        <span className="text-sm text-muted-foreground">
          {ext.caller_id_name || ext.caller_id_number || '-'}
        </span>
      ),
    },
    {
      id: 'voicemail',
      header: t('VoIPPage.extensionColumns.voicemail'),
      cell: (ext) => (
        <Badge variant="outline" className={cn('gap-1', ext.voicemail_enabled ? 'bg-blue-500/10 text-blue-500 border-blue-500/20' : 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20')}>
          <Voicemail className="h-3 w-3" />
          {ext.voicemail_enabled ? t('VoIPPage.common.enabled') : t('VoIPPage.common.disabled')}
        </Badge>
      ),
    },
    {
      id: 'status',
      header: t('VoIPPage.extensionColumns.status'),
      cell: (ext) => (
        <Badge variant="outline" className={cn('gap-1', ext.is_active ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' : 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20')}>
          {ext.is_active ? <CheckCircle className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
          {ext.is_active ? t('VoIPPage.common.active') : t('VoIPPage.common.inactive')}
        </Badge>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: () => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon"><MoreHorizontal className="h-4 w-4" /></Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem><Phone className="h-4 w-4 mr-2" />{t('VoIPPage.extensionActions.viewDetails')}</DropdownMenuItem>
            <DropdownMenuItem><Settings className="h-4 w-4 mr-2" />{t('VoIPPage.extensionActions.settings')}</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ];

  const ringGroupColumns: DataTableColumn<RingGroup>[] = [
    {
      id: 'name',
      header: t('VoIPPage.ringGroupColumns.ringGroup'),
      cell: (rg) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-purple-500/10">
            <Users className="h-4 w-4 text-purple-500" />
          </div>
          <div>
            <div className="font-medium">{rg.name}</div>
            <div className="text-sm text-muted-foreground font-mono">#{rg.group_number}</div>
          </div>
        </div>
      ),
    },
    {
      id: 'strategy',
      header: t('VoIPPage.ringGroupColumns.strategy'),
      cell: (rg) => <StrategyBadge strategy={rg.ring_strategy} />,
    },
    {
      id: 'ring_time',
      header: t('VoIPPage.ringGroupColumns.ringTime'),
      cell: (rg) => <span className="text-sm">{rg.ring_time}s</span>,
    },
    {
      id: 'members',
      header: t('VoIPPage.ringGroupColumns.members'),
      cell: (rg) => (
        <Badge variant="outline" className="gap-1">
          <Users className="h-3 w-3" />
          {t('VoIPPage.ringGroupColumns.membersCount', { count: rg.members?.length ?? 0 })}
        </Badge>
      ),
    },
    {
      id: 'status',
      header: t('VoIPPage.ringGroupColumns.status'),
      cell: (rg) => (
        <Badge variant="outline" className={cn('gap-1', rg.is_active ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' : 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20')}>
          {rg.is_active ? <CheckCircle className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
          {rg.is_active ? t('VoIPPage.common.active') : t('VoIPPage.common.inactive')}
        </Badge>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: (rg) => (
        <Button
          variant="ghost"
          size="sm"
          className="text-destructive"
          onClick={() => {
            if (window.confirm(`${t('common:delete')}, ${rg.name} (#${rg.group_number})`)) {
              deleteRingGroupMutation.mutate(rg.id);
            }
          }}
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      ),
    },
  ];

  const callLogColumns: DataTableColumn<CallLog>[] = [
    {
      id: 'direction',
      header: t('VoIPPage.callLogColumns.direction'),
      cell: (log) => <CallDirectionBadge direction={log.direction} />,
    },
    {
      id: 'caller',
      header: t('VoIPPage.callLogColumns.from'),
      cell: (log) => (
        <div>
          <div className="font-medium">{log.caller_name || log.caller_number}</div>
          {log.caller_name && <div className="text-sm text-muted-foreground font-mono">{log.caller_number}</div>}
        </div>
      ),
    },
    {
      id: 'callee',
      header: t('VoIPPage.callLogColumns.to'),
      cell: (log) => (
        <div>
          <div className="font-medium">{log.callee_name || log.callee_number}</div>
          {log.callee_name && <div className="text-sm text-muted-foreground font-mono">{log.callee_number}</div>}
        </div>
      ),
    },
    {
      id: 'status',
      header: t('VoIPPage.callLogColumns.status'),
      cell: (log) => {
        const sc: Record<string, { icon: typeof PhoneCall; label: string; className: string }> = {
          answered: { icon: PhoneCall, label: t('VoIPPage.callStatus.answered'), className: 'text-emerald-500' },
          missed: { icon: PhoneMissed, label: t('VoIPPage.callStatus.missed'), className: 'text-red-500' },
          voicemail: { icon: Voicemail, label: t('VoIPPage.callStatus.voicemail'), className: 'text-blue-500' },
          failed: { icon: XCircle, label: t('VoIPPage.callStatus.failed'), className: 'text-red-500' },
        };
        const { icon: Icon, label, className } = sc[log.status] || sc.failed;
        return (
          <div className={cn('flex items-center gap-1', className)}>
            <Icon className="h-4 w-4" />
            <span>{label}</span>
          </div>
        );
      },
    },
    {
      id: 'duration',
      header: t('VoIPPage.callLogColumns.duration'),
      cell: (log) => (
        <div className="flex items-center gap-1 text-muted-foreground">
          <Clock className="h-3 w-3" />
          {formatDuration(log.duration_seconds)}
        </div>
      ),
    },
    {
      id: 'start_time',
      header: t('VoIPPage.callLogColumns.time'),
      cell: (log) => (
        <span className="text-sm text-muted-foreground">
          {log.start_time && isValid(new Date(log.start_time))
            ? new Date(log.start_time).toLocaleString()
            : '—'}
        </span>
      ),
    },
    {
      id: 'recording',
      header: '',
      cell: (log) =>
        log.recording_path ? (
          <Button variant="ghost" size="icon" title={t('VoIPPage.callLogColumns.playRecording')}>
            <Play className="h-4 w-4" />
          </Button>
        ) : null,
    },
  ];

  // ─────────────────────────────────────────────────────────────────
  // Tab: Dashboard
  // ─────────────────────────────────────────────────────────────────

  const renderDashboard = () => (
    <div className="space-y-6">
      {/* Stats row */}
      <StatsGrid
        columns={4}
        stats={[
          { title: t('VoIPPage.stats.totalPhones'), value: stats.total, icon: Phone, variant: 'primary' },
          {
            title: t('VoIPPage.stats.online'),
            value: stats.online,
            icon: Wifi,
            variant: 'success',
            description: t('VoIPPage.stats.percentOfFleet', { percent: stats.total ? Math.round((stats.online / stats.total) * 100) : 0 }),
          },
          {
            title: t('VoIPPage.stats.inCall'),
            value: stats.in_call,
            icon: PhoneCall,
            variant: 'warning',
            description: t('VoIPPage.stats.activeRightNow'),
          },
          { title: t('VoIPPage.stats.offline'), value: stats.offline, icon: WifiOff, variant: 'destructive' },
        ]}
      />

      {/* Middle row · PBX status + Trunk status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* PBX Systems */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Server className="h-5 w-5" />
              {t('VoIPPage.dashboard.pbxSystems')}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {pbxSystems.length === 0 ? (
              <EmptyState
                icon={Server}
                title={t('VoIPPage.dashboard.noPbxConfigured')}
                variant="compact"
              />
            ) : (
              pbxSystems.map((pbx) => (
                <div key={pbx.id} className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-3">
                    <div className={cn('w-2.5 h-2.5 rounded-full', pbx.is_active ? 'bg-emerald-500' : 'bg-red-500')} />
                    <div>
                      <p className="font-medium text-sm">{pbx.name}</p>
                      <p className="text-xs text-muted-foreground">{pbx.pbx_type?.toUpperCase() ?? '-'} · {pbx.ip_address || t('VoIPPage.common.notAvailable')}</p>
                    </div>
                  </div>
                  <PBXTypeBadge type={pbx.pbx_type} />
                </div>
              ))
            )}
          </CardContent>
        </Card>

        {/* SIP Trunks */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Route className="h-5 w-5" />
              {t('VoIPPage.dashboard.sipTrunks')}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {trunks.map((trunk) => (
              <div key={trunk.id} className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                <div className="flex items-center gap-3">
                  <div className={cn('w-2.5 h-2.5 rounded-full', trunk.is_registered ? 'bg-emerald-500' : 'bg-red-500')} />
                  <div>
                    <p className="font-medium text-sm">{trunk.name}</p>
                    <p className="text-xs text-muted-foreground">{trunk.provider} · {trunk.host}</p>
                  </div>
                </div>
                <span className="text-sm text-muted-foreground">{t('VoIPPage.dashboard.channels', { active: trunk.active_channels, max: trunk.max_channels })}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Queue status cards */}
      {queues.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {queues.map((queue) => (
            <Card key={queue.id}>
              <CardContent noOffset>
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <p className="font-semibold">{queue.name}</p>
                    <p className="text-sm text-muted-foreground">{t('VoIPPage.queues.queueNumber', { number: queue.queue_number })}</p>
                  </div>
                  {queue.calls_waiting > 0 && (
                    <Badge variant="outline" className="bg-amber-500/10 text-amber-500 border-amber-500/20">
                      {t('VoIPPage.queues.callsWaiting', { count: queue.calls_waiting })}
                    </Badge>
                  )}
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 text-center">
                  <div>
                    <p className="text-2xl font-bold text-blue-500">{queue.current_callers}</p>
                    <p className="text-xs text-muted-foreground">{t('VoIPPage.queues.inQueue')}</p>
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-emerald-500">{queue.available_agents}</p>
                    <p className="text-xs text-muted-foreground">{t('VoIPPage.queues.agents')}</p>
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-muted-foreground">{queue.calls_waiting}</p>
                    <p className="text-xs text-muted-foreground">{t('VoIPPage.queues.waiting')}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Extensions + Ring Groups + Voicemail summary */}
      <StatsGrid
        columns={3}
        stats={[
          {
            title: t('VoIPPage.summary.extensions'),
            value: extensions.length,
            icon: Hash,
            variant: 'primary',
            description: t('VoIPPage.summary.activeCount', { count: extensions.filter((e) => e.is_active).length }),
          },
          { title: t('VoIPPage.summary.ringGroups'), value: ringGroups.length, icon: Users, variant: 'primary' },
          {
            title: t('VoIPPage.summary.voicemails'),
            value: unreadVoicemails,
            icon: Voicemail,
            variant: 'warning',
            description: t('VoIPPage.summary.unreadMessages'),
          },
        ]}
      />

      {/* Recent calls */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-base">
              <Clock className="h-5 w-5" />
              {t('VoIPPage.dashboard.recentCalls')}
            </CardTitle>
            <Button variant="ghost" size="sm" className="gap-1 text-sm" onClick={() => handleTabChange('calls')}>
              {t('VoIPPage.dashboard.viewAll')} <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </CardHeader>
        <CardContent className="pt-0">
          <DataTable
            data={callLogs.slice(0, 5)}
            columns={callLogColumns}
            isLoading={logsLoading}
            searchable={false}
            paginated={false}
            itemName={t('VoIPPage.itemNames.calls')}
          />
        </CardContent>
      </Card>
    </div>
  );

  // ─────────────────────────────────────────────────────────────────
  // Tab: Phones
  // ─────────────────────────────────────────────────────────────────

  const renderPhones = () => (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <SearchBar
            value={searchQuery}
            onChange={setSearchQuery}
            placeholder={t('VoIPPage.phones.searchPlaceholder')}
          />
          <Button variant="outline" size="icon" title={t('VoIPPage.common.filter')}>
            <Filter className="h-4 w-4" />
          </Button>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex border border-border rounded-md overflow-hidden">
            <Button
              variant={phoneView === 'grid' ? 'secondary' : 'ghost'}
              size="sm"
              className="rounded-none"
              onClick={() => setPhoneView('grid')}
            >
              <BarChart3 className="h-4 w-4" />
            </Button>
            <Button
              variant={phoneView === 'table' ? 'secondary' : 'ghost'}
              size="sm"
              className="rounded-none"
              onClick={() => setPhoneView('table')}
            >
              <List className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>

      {/* Grandstream GDMS-style device management banner */}
      <Card className="border-blue-500/20 bg-blue-500/5">
        <CardContent noOffset className="flex items-center justify-between py-3">
          <div className="flex items-center gap-3">
            <Shield className="h-5 w-5 text-blue-500" />
            <div>
              <p className="text-sm font-medium">{t('VoIPPage.phones.zeroTouchTitle')}</p>
              <p className="text-xs text-muted-foreground">
                {t('VoIPPage.phones.zeroTouchDescription')}
              </p>
            </div>
          </div>
          <Button variant="outline" size="sm">
            <Settings className="h-4 w-4 mr-2" />
            {t('VoIPPage.phones.provisioningSettings')}
          </Button>
        </CardContent>
      </Card>

      {phoneView === 'grid' ? (
        phonesLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <Card key={i} className="animate-pulse">
                <CardContent noOffset className="pb-4 space-y-3">
                  <div className="flex items-center gap-3">
                    <div className="h-12 w-12 rounded-lg bg-muted" />
                    <div className="space-y-2 flex-1">
                      <div className="h-4 w-32 bg-muted rounded" />
                      <div className="h-3 w-24 bg-muted rounded" />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="h-3 w-full bg-muted rounded" />
                    <div className="h-3 w-full bg-muted rounded" />
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : filteredPhones.length === 0 ? (
          searchQuery ? (
            <NoResultsState searchQuery={searchQuery} onClear={() => setSearchQuery('')} />
          ) : (
            <EmptyState
              icon={Phone}
              title={t('VoIPPage.phones.emptyTitle')}
              description={t('VoIPPage.phones.emptyDescription')}
            />
          )
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredPhones.map((phone) => (
              <PhoneDeviceCard key={phone.id} phone={phone} />
            ))}
          </div>
        )
      ) : (
        <DataTable
          data={filteredPhones}
          columns={phoneColumns}
          isLoading={phonesLoading}
          searchable={false}
          itemName={t('VoIPPage.itemNames.phones')}
        />
      )}
    </div>
  );

  // ─────────────────────────────────────────────────────────────────
  // Tab: PBX Systems
  // ─────────────────────────────────────────────────────────────────

  const renderPBX = () => (
    <div className="space-y-4">
      {/* PBX integration banner */}
      <Card className="border-orange-500/20 bg-orange-500/5">
        <CardContent noOffset className="flex items-center justify-between py-3">
          <div className="flex items-center gap-3">
            <Server className="h-5 w-5 text-orange-500" />
            <div>
              <p className="text-sm font-medium">{t('VoIPPage.pbxTab.bannerTitle')}</p>
              <p className="text-xs text-muted-foreground">
                {t('VoIPPage.pbxTab.bannerDescription')}
              </p>
            </div>
          </div>
          <Button variant="outline" size="sm" onClick={() => setShowAddPBX(true)}>
            <Plus className="h-4 w-4 mr-2" />
            {t('VoIPPage.pbxTab.addPbx')}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('VoIPPage.pbxTab.cardTitle')}</CardTitle>
          <CardDescription>{t('VoIPPage.pbxTab.cardDescription')}</CardDescription>
        </CardHeader>
        <DataTable
          embedded
          data={pbxSystems}
          columns={pbxColumns}
          isLoading={pbxLoading}
          searchable={false}
          itemName={t('VoIPPage.itemNames.pbxSystems')}
          emptyState={
            <EmptyState
              icon={Server}
              title={t('VoIPPage.pbxTab.emptyTitle')}
              description={t('VoIPPage.pbxTab.emptyDescription')}
              action={{ label: t('VoIPPage.pbxTab.addPbxSystem'), onClick: () => setShowAddPBX(true) }}
            />
          }
        />
      </Card>
    </div>
  );

  // ─────────────────────────────────────────────────────────────────
  // Tab: Extensions
  // ─────────────────────────────────────────────────────────────────

  const renderExtensions = () => (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <SearchBar
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder={t('VoIPPage.extensionsTab.searchPlaceholder')}
        />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>{t('VoIPPage.extensionsTab.cardTitle')}</CardTitle>
          <CardDescription>{t('VoIPPage.extensionsTab.cardDescription')}</CardDescription>
        </CardHeader>
        <DataTable
          embedded
          data={filteredExtensions}
          columns={extensionColumns}
          isLoading={extensionsLoading}
          searchable={false}
          itemName={t('VoIPPage.itemNames.extensions')}
        />
      </Card>
    </div>
  );

  // ─────────────────────────────────────────────────────────────────
  // Tab: Ring Groups
  // ─────────────────────────────────────────────────────────────────

  const renderRingGroups = () => (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>{t('VoIPPage.ringGroupsTab.cardTitle')}</CardTitle>
            <CardDescription>{t('VoIPPage.ringGroupsTab.cardDescription')}</CardDescription>
          </div>
          <Button
            onClick={() => {
              const defaultPbx = pbxSystems.length === 1 ? pbxSystems[0].id : '';
              setRgForm({ ...emptyRgForm, pbx_id: defaultPbx });
              setShowAddRingGroup(true);
            }}
            disabled={pbxSystems.length === 0}
          >
            <Plus className="h-4 w-4 mr-2" />
            {t('VoIPPage.ringGroupsTab.addRingGroup')}
          </Button>
        </CardHeader>
        <DataTable
          embedded
          data={ringGroups}
          columns={ringGroupColumns}
          isLoading={ringGroupsLoading}
          searchable={false}
          itemName={t('VoIPPage.itemNames.ringGroups')}
          emptyState={
            <EmptyState
              icon={Users}
              title={t('VoIPPage.ringGroupsTab.emptyTitle')}
              description={t('VoIPPage.ringGroupsTab.emptyDescription')}
            />
          }
        />
      </Card>
    </div>
  );

  // ─────────────────────────────────────────────────────────────────
  // Tab: Queues
  // ─────────────────────────────────────────────────────────────────

  const renderQueues = () => (
    <div className="space-y-4">
      {queues.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {queues.map((queue) => (
            <Card key={queue.id}>
              <CardContent noOffset>
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <p className="font-semibold">{queue.name}</p>
                    <p className="text-sm text-muted-foreground">{t('VoIPPage.queues.queueNumberStrategy', { number: queue.queue_number, strategy: queue.strategy })}</p>
                  </div>
                  {queue.calls_waiting > 0 && (
                    <Badge variant="outline" className="bg-amber-500/10 text-amber-500 border-amber-500/20">
                      {t('VoIPPage.queues.callsWaiting', { count: queue.calls_waiting })}
                    </Badge>
                  )}
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 text-center">
                  <div>
                    <p className="text-2xl font-bold text-blue-500">{queue.current_callers}</p>
                    <p className="text-xs text-muted-foreground">{t('VoIPPage.queues.inQueue')}</p>
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-emerald-500">{queue.available_agents}</p>
                    <p className="text-xs text-muted-foreground">{t('VoIPPage.queues.agents')}</p>
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-muted-foreground">{queue.calls_waiting}</p>
                    <p className="text-xs text-muted-foreground">{t('VoIPPage.queues.waiting')}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <EmptyState
          icon={List}
          title={t('VoIPPage.queues.emptyTitle')}
          description={t('VoIPPage.queues.emptyDescription')}
          variant="card"
        />
      )}
    </div>
  );

  // ─────────────────────────────────────────────────────────────────
  // Tab: Call History
  // ─────────────────────────────────────────────────────────────────

  const renderCallHistory = () => (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <SearchBar
            value={searchQuery}
            onChange={setSearchQuery}
            placeholder={t('VoIPPage.callHistory.searchPlaceholder')}
          />
          <Button variant="outline" size="icon" title={t('VoIPPage.common.filter')}>
            <Filter className="h-4 w-4" />
          </Button>
        </div>
        <Button variant="outline" onClick={exportCallLogsCsv} disabled={callLogs.length === 0}>
          <Download className="h-4 w-4 mr-2" />
          {t('VoIPPage.callHistory.exportCdr')}
        </Button>
      </div>

      <DataTable
        data={callLogs}
        columns={callLogColumns}
        isLoading={logsLoading}
        searchable={false}
        itemName={t('VoIPPage.itemNames.callRecords')}
      />
    </div>
  );

  // ─────────────────────────────────────────────────────────────────
  // Tab: Voicemail
  // ─────────────────────────────────────────────────────────────────

  const renderVoicemail = () => {
    const filteredVoicemails = voicemails.filter(
      (vm) =>
        vm.caller_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        vm.caller_name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        vm.extension_number?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        vm.transcription?.toLowerCase().includes(searchQuery.toLowerCase()),
    );

    return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <SearchBar
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder={t('VoIPPage.voicemail.searchPlaceholder')}
        />
        <Button variant="outline" size="sm" onClick={() => refetchVoicemails()} disabled={voicemailsLoading}>
          <RefreshCw className={cn('h-4 w-4 mr-2', voicemailsLoading && 'animate-spin')} />
          {t('VoIPPage.voicemail.refresh')}
        </Button>
        {voicemailStats.unread > 0 && (
          <Badge variant="secondary">{t('VoIPPage.voicemail.unreadBadge', { count: voicemailStats.unread })}</Badge>
        )}
      </div>

      {voicemailsLoading ? (
        <div className="flex items-center justify-center py-16">
          <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : filteredVoicemails.length === 0 ? (
        <EmptyState
          icon={Voicemail}
          title={t('VoIPPage.voicemail.emptyTitle')}
          description={t('VoIPPage.voicemail.emptyDescription')}
          variant="card"
        />
      ) : (
        <div className="space-y-2">
          {filteredVoicemails.map((vm) => (
            <Card
              key={vm.id}
              className={cn(
                'transition-colors',
                !vm.is_read && 'border-blue-500/30 bg-blue-500/5',
              )}
            >
              <CardContent noOffset className="flex items-center justify-between py-3">
                <div className="flex items-center gap-3">
                  <div className={cn('p-2 rounded-full', vm.is_urgent ? 'bg-red-500/10 text-red-500' : 'bg-muted text-muted-foreground')}>
                    <Voicemail className="h-5 w-5" />
                  </div>
                  <div>
                    <p className="font-medium flex items-center gap-2">
                      {vm.caller_id}
                      {vm.is_urgent && (
                        <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/20 text-xs">{t('VoIPPage.voicemail.urgent')}</Badge>
                      )}
                      {!vm.is_read && (
                        <Badge variant="outline" className="bg-blue-500/10 text-blue-500 border-blue-500/20 text-xs">{t('VoIPPage.voicemail.new')}</Badge>
                      )}
                    </p>
                    <p className="text-sm text-muted-foreground">
                      {t('VoIPPage.voicemail.extDate', { ext: vm.extension_number, date: vm.message_date && isValid(new Date(vm.message_date)) ? new Date(vm.message_date).toLocaleString() : '—' })}
                    </p>
                    {vm.transcription && (
                      <p className="text-sm text-muted-foreground mt-1 max-w-lg truncate">{vm.transcription}</p>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <span className="text-sm text-muted-foreground mr-2">
                    {Math.floor((vm.duration ?? 0) / 60)}:{((vm.duration ?? 0) % 60).toString().padStart(2, '0')}
                  </span>
                  <Button
                    variant="ghost"
                    size="icon"
                    title={vm.is_read ? t('VoIPPage.voicemail.play') : t('VoIPPage.voicemail.playMarkRead')}
                    onClick={() => {
                      if (!vm.is_read) markVoicemailReadMutation.mutate(vm.id);
                    }}
                  >
                    <Play className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    disabled
                    title={t('VoIPPage.voicemail.downloadUnavailable')}
                  >
                    <Download className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    title={t('VoIPPage.voicemail.delete')}
                    className="text-destructive hover:text-destructive/80 hover:bg-destructive/10"
                    onClick={() => {
                      if (window.confirm(t('VoIPPage.confirm.deleteVoicemail'))) {
                        deleteVoicemailMutation.mutate(vm.id);
                      }
                    }}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
    );
  };

  // ─────────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────────

  const hasQueryError = phonesError || statsError || pbxError || extensionsError || ringGroupsError || logsError || voicemailsError;

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={Phone}
        title={t('VoIPPage.header.title')}
        subtitle={t('VoIPPage.header.subtitle')}
        onRefresh={() => {
          refetchPhones();
          refetchPBX();
          refetchLogs();
          refetchVoicemails();
        }}
        refreshing={phonesLoading}
        primaryAction={{
          label: t('VoIPPage.header.addPhone'),
          icon: Plus,
          onClick: () => setShowAddPhone(true),
        }}
      />

      {hasQueryError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('VoIPPage.errorBanner')}</span>
          </CardContent>
        </Card>
      )}

      {/* Stats bar */}
      <StatsGrid
        columns={4}
        stats={[
          { title: t('VoIPPage.stats.totalPhones'), value: stats.total, icon: Phone, variant: 'primary' },
          { title: t('VoIPPage.stats.online'), value: stats.online, icon: CheckCircle, variant: 'success' },
          { title: t('VoIPPage.stats.inCall'), value: stats.in_call, icon: PhoneCall, variant: 'warning' },
          { title: t('VoIPPage.stats.offline'), value: stats.offline, icon: PhoneOff, variant: 'default' },
        ]}
      />

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={handleTabChange}>
        <TabsList>
          <TabsTrigger value="dashboard" className="gap-1.5">
            <BarChart3 className="h-4 w-4" />
            {t('VoIPPage.tabs.dashboard')}
          </TabsTrigger>
          <TabsTrigger value="phones" className="gap-1.5">
            <Phone className="h-4 w-4" />
            {t('VoIPPage.tabs.phones')}
          </TabsTrigger>
          <TabsTrigger value="pbx" className="gap-1.5">
            <Server className="h-4 w-4" />
            {t('VoIPPage.tabs.pbxSystems')}
          </TabsTrigger>
          <TabsTrigger value="extensions" className="gap-1.5">
            <Hash className="h-4 w-4" />
            {t('VoIPPage.tabs.extensions')}
          </TabsTrigger>
          <TabsTrigger value="ringgroups" className="gap-1.5">
            <Users className="h-4 w-4" />
            {t('VoIPPage.tabs.ringGroups')}
          </TabsTrigger>
          <TabsTrigger value="queues" className="gap-1.5">
            <List className="h-4 w-4" />
            {t('VoIPPage.tabs.queues')}
          </TabsTrigger>
          <TabsTrigger value="calls" className="gap-1.5">
            <Clock className="h-4 w-4" />
            {t('VoIPPage.tabs.callHistory')}
          </TabsTrigger>
          <TabsTrigger value="voicemail" className="gap-1.5 relative">
            <Voicemail className="h-4 w-4" />
            {t('VoIPPage.tabs.voicemail')}
            {unreadVoicemails > 0 && (
              <span className="absolute -top-1 -right-1 h-4 min-w-[16px] flex items-center justify-center text-[10px] font-bold bg-destructive text-destructive-foreground rounded-full px-1">
                {unreadVoicemails}
              </span>
            )}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="dashboard" className="mt-6">{renderDashboard()}</TabsContent>
        <TabsContent value="phones" className="mt-6">{renderPhones()}</TabsContent>
        <TabsContent value="pbx" className="mt-6">{renderPBX()}</TabsContent>
        <TabsContent value="extensions" className="mt-6">{renderExtensions()}</TabsContent>
        <TabsContent value="ringgroups" className="mt-6">{renderRingGroups()}</TabsContent>
        <TabsContent value="queues" className="mt-6">{renderQueues()}</TabsContent>
        <TabsContent value="calls" className="mt-6">{renderCallHistory()}</TabsContent>
        <TabsContent value="voicemail" className="mt-6">{renderVoicemail()}</TabsContent>
      </Tabs>

      {/* ─── Add PBX Dialog ────────────────────────────────────── */}
      <AddPBXDialog
        open={showAddPBX}
        onOpenChange={setShowAddPBX}
        onSubmit={(data) => createPBXMutation.mutate(data)}
        onTestConnection={(data) => testConnectionMutation.mutateAsync(data)}
        isSubmitting={createPBXMutation.isPending}
        testResult={testConnectionMutation.data?.data ?? null}
        isTesting={testConnectionMutation.isPending}
      />

      {/* ─── Add Phone Dialog ───────────────────────────────────── */}
      <AddPhoneDialog
        open={showAddPhone}
        onOpenChange={setShowAddPhone}
        onSubmit={(data) => createPhoneMutation.mutate(data)}
        isSubmitting={createPhoneMutation.isPending}
        pbxSystems={pbxSystems}
      />

      {/* ─── Add Ring Group Dialog ──────────────────────────────── */}
      <Dialog open={showAddRingGroup} onOpenChange={setShowAddRingGroup}>
        <DialogContent className="sm:max-w-[480px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Users className="h-5 w-5" />
              {t('VoIPPage.ringGroupsTab.addRingGroup')}
            </DialogTitle>
            <DialogDescription>{t('VoIPPage.ringGroupsTab.cardDescription')}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label>{t('VoIPPage.ringGroupColumns.ringGroup')}</Label>
              <Select value={rgForm.pbx_id} onValueChange={(v) => setRgForm((f) => ({ ...f, pbx_id: v }))}>
                <SelectTrigger>
                  <SelectValue placeholder="PBX" />
                </SelectTrigger>
                <SelectContent>
                  {pbxSystems.map((p) => (
                    <SelectItem key={p.id} value={p.id}>{p.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label>#</Label>
                <Input
                  placeholder="600"
                  value={rgForm.group_number}
                  onChange={(e) => setRgForm((f) => ({ ...f, group_number: e.target.value }))}
                />
              </div>
              <div className="space-y-2">
                <Label>{t('VoIPPage.ringGroupColumns.ringTime')}</Label>
                <Input
                  type="number"
                  min={1}
                  max={300}
                  value={rgForm.ring_time}
                  onChange={(e) => setRgForm((f) => ({ ...f, ring_time: Number(e.target.value) }))}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label>{t('VoIPPage.ringGroupColumns.ringGroup')}</Label>
              <Input
                value={rgForm.name}
                onChange={(e) => setRgForm((f) => ({ ...f, name: e.target.value }))}
              />
            </div>
            <div className="space-y-2">
              <Label>{t('VoIPPage.ringGroupColumns.strategy')}</Label>
              <Select value={rgForm.ring_strategy} onValueChange={(v) => setRgForm((f) => ({ ...f, ring_strategy: v }))}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ringall">{t('VoIPPage.ringStrategy.ringall')}</SelectItem>
                  <SelectItem value="hunt">{t('VoIPPage.ringStrategy.hunt')}</SelectItem>
                  <SelectItem value="memoryhunt">{t('VoIPPage.ringStrategy.memoryhunt')}</SelectItem>
                  <SelectItem value="random">{t('VoIPPage.ringStrategy.random')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>{t('VoIPPage.ringGroupColumns.members')}</Label>
              <Input
                placeholder="100, 101, 102"
                value={rgForm.members}
                onChange={(e) => setRgForm((f) => ({ ...f, members: e.target.value }))}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddRingGroup(false)}>
              {t('common:cancel')}
            </Button>
            <Button
              onClick={() => createRingGroupMutation.mutate()}
              disabled={!rgForm.pbx_id || !rgForm.group_number || !rgForm.name || createRingGroupMutation.isPending}
            >
              {createRingGroupMutation.isPending ? t('common:loading') : t('common:create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
