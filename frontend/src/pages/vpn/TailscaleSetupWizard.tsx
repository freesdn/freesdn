/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Loader2,
  Copy,
  ExternalLink,
  Globe,
  Key,
  Settings,
  Wifi,
  WifiOff,
  RefreshCw,
  LogOut,
  Power,
  Eye,
  EyeOff,
  ChevronRight,
  Zap,
  Lock,
  Info,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';
import {
  vpnApi,
  type TailscaleSetupStatus,
  type TailscaleSetupState,
  type TailscaleAuthKeyLogin,
  type TailscaleConfigureRequest,
} from '@/lib/api';

// ─── State Visual Mapping ────────────────────────────────────────────────────

type StateConfigEntry = {
  label: string;
  color: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
};

const buildStateConfig = (
  t: (key: string) => string,
): Record<TailscaleSetupState, StateConfigEntry> => ({
  not_installed: {
    label: t('TailscaleSetupWizard.states.not_installed.label'),
    color: 'text-muted-foreground bg-muted border-border',
    icon: XCircle,
    description: t('TailscaleSetupWizard.states.not_installed.description'),
  },
  daemon_stopped: {
    label: t('TailscaleSetupWizard.states.daemon_stopped.label'),
    color: 'text-orange-600 bg-orange-50 border-orange-200 dark:bg-orange-950/30 dark:border-orange-800',
    icon: AlertTriangle,
    description: t('TailscaleSetupWizard.states.daemon_stopped.description'),
  },
  needs_login: {
    label: t('TailscaleSetupWizard.states.needs_login.label'),
    color: 'text-yellow-600 bg-yellow-50 border-yellow-200 dark:bg-yellow-950/30 dark:border-yellow-800',
    icon: Key,
    description: t('TailscaleSetupWizard.states.needs_login.description'),
  },
  awaiting_auth: {
    label: t('TailscaleSetupWizard.states.awaiting_auth.label'),
    color: 'text-blue-600 bg-blue-50 border-blue-200 dark:bg-blue-950/30 dark:border-blue-800',
    icon: Loader2,
    description: t('TailscaleSetupWizard.states.awaiting_auth.description'),
  },
  connected: {
    label: t('TailscaleSetupWizard.states.connected.label'),
    color: 'text-green-600 bg-green-50 border-green-200 dark:bg-green-950/30 dark:border-green-800',
    icon: CheckCircle,
    description: t('TailscaleSetupWizard.states.connected.description'),
  },
  error: {
    label: t('TailscaleSetupWizard.states.error.label'),
    color: 'text-red-600 bg-red-50 border-red-200 dark:bg-red-950/30 dark:border-red-800',
    icon: XCircle,
    description: t('TailscaleSetupWizard.states.error.description'),
  },
});

// ─── Setup Status Banner ─────────────────────────────────────────────────────

function SetupStatusBanner({ status }: { status: TailscaleSetupStatus }) {
  const { t } = useTranslation('vpn');
  const stateConfig = buildStateConfig(t);
  const config = stateConfig[status.state] || stateConfig.error;
  const Icon = config.icon;

  return (
    <div className={`rounded-lg border p-4 ${config.color}`}>
      <div className="flex items-start gap-3">
        <Icon className={`h-5 w-5 mt-0.5 ${status.state === 'awaiting_auth' ? 'animate-spin' : ''}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-semibold">{config.label}</span>
            {status.version && (
              <Badge variant="outline" className="text-xs font-mono">
                v{status.version}
              </Badge>
            )}
          </div>
          <p className="text-sm opacity-80">{config.description}</p>
          {status.message && status.state === 'error' && (
            <p className="text-sm mt-1 font-mono">{status.message}</p>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Connected Info Panel ────────────────────────────────────────────────────

function ConnectedInfoPanel({ status }: { status: TailscaleSetupStatus }) {
  const { toast } = useToast();
  const { t } = useTranslation('vpn');

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text).then(
      () => toast({ title: t('TailscaleSetupWizard.toast.copied.title'), description: t('TailscaleSetupWizard.toast.copied.description', { label }) }),
      () => toast({ title: t('TailscaleSetupWizard.toast.copyFailed.title'), description: t('TailscaleSetupWizard.toast.copyFailed.description'), variant: 'destructive' }),
    );
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <Globe className="h-4 w-4 text-blue-500" />
          {t('TailscaleSetupWizard.nodeInfo.title')}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Hostname */}
          <div className="space-y-1">
            <span className="text-xs text-muted-foreground uppercase tracking-wide">{t('TailscaleSetupWizard.nodeInfo.hostname')}</span>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-medium">{status.hostname || t('TailscaleSetupWizard.nodeInfo.notAvailable')}</span>
              {status.hostname && (
                <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => copyToClipboard(status.hostname!, t('TailscaleSetupWizard.nodeInfo.hostname'))}>
                  <Copy className="h-3 w-3" />
                </Button>
              )}
            </div>
          </div>

          {/* Tailscale IP */}
          <div className="space-y-1">
            <span className="text-xs text-muted-foreground uppercase tracking-wide">{t('TailscaleSetupWizard.nodeInfo.tailscaleIp')}</span>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-medium">{status.tailscale_ip || t('TailscaleSetupWizard.nodeInfo.notAvailable')}</span>
              {status.tailscale_ip && (
                <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => copyToClipboard(status.tailscale_ip!, t('TailscaleSetupWizard.nodeInfo.tailscaleIp'))}>
                  <Copy className="h-3 w-3" />
                </Button>
              )}
            </div>
          </div>

          {/* Tailnet */}
          <div className="space-y-1">
            <span className="text-xs text-muted-foreground uppercase tracking-wide">{t('TailscaleSetupWizard.nodeInfo.tailnet')}</span>
            <span className="font-mono text-sm block">{status.tailnet || t('TailscaleSetupWizard.nodeInfo.notAvailable')}</span>
          </div>

          {/* MagicDNS */}
          <div className="space-y-1">
            <span className="text-xs text-muted-foreground uppercase tracking-wide">{t('TailscaleSetupWizard.nodeInfo.magicDns')}</span>
            <div className="flex items-center gap-2">
              {status.magic_dns_enabled ? (
                <Badge variant="outline" className="text-xs text-green-600 border-green-300">{t('TailscaleSetupWizard.nodeInfo.enabled')}</Badge>
              ) : (
                <Badge variant="outline" className="text-xs">{t('TailscaleSetupWizard.nodeInfo.disabled')}</Badge>
              )}
              {status.magic_dns_suffix && (
                <span className="text-xs text-muted-foreground font-mono">{status.magic_dns_suffix}</span>
              )}
            </div>
          </div>

          {/* Peer Count */}
          <div className="space-y-1">
            <span className="text-xs text-muted-foreground uppercase tracking-wide">{t('TailscaleSetupWizard.nodeInfo.peers')}</span>
            <span className="text-sm font-medium">{t('TailscaleSetupWizard.nodeInfo.peerCount', { count: status.peer_count ?? 0 })}</span>
          </div>

          {/* Additional IPs */}
          {status.tailscale_ips && status.tailscale_ips.length > 1 && (
            <div className="space-y-1">
              <span className="text-xs text-muted-foreground uppercase tracking-wide">{t('TailscaleSetupWizard.nodeInfo.ipv6')}</span>
              <span className="font-mono text-xs block truncate">{status.tailscale_ips[1]}</span>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Auth Key Login Form ─────────────────────────────────────────────────────

function AuthKeyLoginForm({
  onLogin,
  isLoading,
}: {
  onLogin: (data: TailscaleAuthKeyLogin) => void;
  isLoading: boolean;
}) {
  const { t } = useTranslation('vpn');
  const [authKey, setAuthKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [hostname, setHostname] = useState('freesdn-controller');
  const [acceptRoutes, setAcceptRoutes] = useState(true);
  const [advertiseRoutes, setAdvertiseRoutes] = useState('');
  const [advertiseExitNode, setAdvertiseExitNode] = useState(false);
  const [shieldsUp, setShieldsUp] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!authKey.trim()) return;
    onLogin({
      auth_key: authKey.trim(),
      hostname: hostname.trim() || undefined,
      accept_routes: acceptRoutes,
      advertise_routes: advertiseRoutes ? advertiseRoutes.split(',').map(r => r.trim()).filter(Boolean) : undefined,
      advertise_exit_node: advertiseExitNode,
      shields_up: shieldsUp,
    });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {/* Auth Key */}
      <div className="space-y-2">
        <Label htmlFor="authKey" className="flex items-center gap-1.5">
          <Key className="h-3.5 w-3.5" />
          {t('TailscaleSetupWizard.authKeyForm.authKeyLabel')}
        </Label>
        <div className="relative">
          <Input
            id="authKey"
            type={showKey ? 'text' : 'password'}
            placeholder="tskey-auth-..."
            value={authKey}
            onChange={(e) => setAuthKey(e.target.value)}
            className="pr-10 font-mono text-sm"
            autoComplete="off"
          />
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7"
            onClick={() => setShowKey(!showKey)}
          >
            {showKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          {t('TailscaleSetupWizard.authKeyForm.authKeyHelpPrefix')}{' '}
          <a href="https://login.tailscale.com/admin/settings/keys" target="_blank" rel="noopener noreferrer" className="underline hover:text-foreground">
            {t('TailscaleSetupWizard.adminConsole')}
          </a>
          {t('TailscaleSetupWizard.authKeyForm.authKeyHelpSuffix')}
        </p>
      </div>

      {/* Hostname */}
      <div className="space-y-2">
        <Label htmlFor="hostname">{t('TailscaleSetupWizard.fields.hostname')}</Label>
        <Input
          id="hostname"
          placeholder="freesdn-controller"
          value={hostname}
          onChange={(e) => setHostname(e.target.value)}
          className="font-mono text-sm"
        />
        <p className="text-xs text-muted-foreground">
          {t('TailscaleSetupWizard.fields.hostnameHelp')}
        </p>
      </div>

      {/* Advanced Options Toggle */}
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="text-xs text-muted-foreground"
        onClick={() => setShowAdvanced(!showAdvanced)}
      >
        <Settings className="mr-1 h-3 w-3" />
        {showAdvanced ? t('TailscaleSetupWizard.advanced.hide') : t('TailscaleSetupWizard.advanced.show')}{' '}
        {t('TailscaleSetupWizard.advanced.label')}
        <ChevronRight className={`ml-1 h-3 w-3 transition-transform ${showAdvanced ? 'rotate-90' : ''}`} />
      </Button>

      <AnimatePresence>
        {showAdvanced && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="space-y-4 overflow-hidden"
          >
            {/* Accept Routes */}
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div className="space-y-0.5">
                <Label className="text-sm">{t('TailscaleSetupWizard.options.acceptRoutes.label')}</Label>
                <p className="text-xs text-muted-foreground">{t('TailscaleSetupWizard.options.acceptRoutes.descriptionLogin')}</p>
              </div>
              <Switch checked={acceptRoutes} onCheckedChange={setAcceptRoutes} />
            </div>

            {/* Advertise Routes */}
            <div className="space-y-2">
              <Label>{t('TailscaleSetupWizard.options.advertiseRoutes.label')}</Label>
              <Input
                placeholder="10.0.0.0/24, 192.168.1.0/24"
                value={advertiseRoutes}
                onChange={(e) => setAdvertiseRoutes(e.target.value)}
                className="font-mono text-sm"
              />
              <p className="text-xs text-muted-foreground">
                {t('TailscaleSetupWizard.options.advertiseRoutes.description')}
              </p>
            </div>

            {/* Exit Node */}
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div className="space-y-0.5">
                <Label className="text-sm">{t('TailscaleSetupWizard.options.exitNode.label')}</Label>
                <p className="text-xs text-muted-foreground">{t('TailscaleSetupWizard.options.exitNode.description')}</p>
              </div>
              <Switch checked={advertiseExitNode} onCheckedChange={setAdvertiseExitNode} />
            </div>

            {/* Shields Up */}
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div className="space-y-0.5">
                <Label className="text-sm">{t('TailscaleSetupWizard.options.shieldsUp.label')}</Label>
                <p className="text-xs text-muted-foreground">{t('TailscaleSetupWizard.options.shieldsUp.descriptionLogin')}</p>
              </div>
              <Switch checked={shieldsUp} onCheckedChange={setShieldsUp} />
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Submit */}
      <Button type="submit" className="w-full" disabled={!authKey.trim() || isLoading}>
        {isLoading ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            {t('TailscaleSetupWizard.authKeyForm.authenticating')}
          </>
        ) : (
          <>
            <Lock className="mr-2 h-4 w-4" />
            {t('TailscaleSetupWizard.authKeyForm.connect')}
          </>
        )}
      </Button>
    </form>
  );
}

// ─── Interactive Login Panel ─────────────────────────────────────────────────

function InteractiveLoginPanel({
  loginUrl,
  onStartLogin,
  isLoading,
}: {
  loginUrl?: string;
  onStartLogin: (hostname?: string) => void;
  isLoading: boolean;
}) {
  const { toast } = useToast();
  const { t } = useTranslation('vpn');
  const [hostname, setHostname] = useState('freesdn-controller');

  const copyUrl = () => {
    if (loginUrl) {
      navigator.clipboard.writeText(loginUrl).then(
        () => toast({ title: t('TailscaleSetupWizard.toast.copied.title'), description: t('TailscaleSetupWizard.toast.loginUrlCopied') }),
        () => toast({ title: t('TailscaleSetupWizard.toast.copyFailed.title'), description: t('TailscaleSetupWizard.toast.copyFailed.description'), variant: 'destructive' }),
      );
    }
  };

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label>{t('TailscaleSetupWizard.fields.hostname')}</Label>
        <Input
          placeholder="freesdn-controller"
          value={hostname}
          onChange={(e) => setHostname(e.target.value)}
          className="font-mono text-sm"
        />
      </div>

      {!loginUrl ? (
        <Button
          onClick={() => onStartLogin(hostname.trim() || undefined)}
          className="w-full"
          disabled={isLoading}
        >
          {isLoading ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              {t('TailscaleSetupWizard.interactive.generating')}
            </>
          ) : (
            <>
              <Globe className="mr-2 h-4 w-4" />
              {t('TailscaleSetupWizard.interactive.loginViaBrowser')}
            </>
          )}
        </Button>
      ) : (
        <div className="space-y-3">
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              {t('TailscaleSetupWizard.interactive.openUrlInstruction')}
            </AlertDescription>
          </Alert>

          <div className="flex items-center gap-2 rounded-lg border bg-muted/50 p-3">
            <code className="flex-1 text-xs font-mono break-all select-all">{loginUrl}</code>
            <Button variant="outline" size="sm" onClick={copyUrl}>
              <Copy className="h-3 w-3 mr-1" />
              {t('TailscaleSetupWizard.actions.copy')}
            </Button>
          </div>

          <div className="flex gap-2">
            <a href={loginUrl} target="_blank" rel="noopener noreferrer" className="flex-1">
              <Button variant="default" className="w-full">
                <ExternalLink className="mr-2 h-4 w-4" />
                {t('TailscaleSetupWizard.interactive.openInBrowser')}
              </Button>
            </a>
          </div>

          <p className="text-xs text-muted-foreground text-center">
            {t('TailscaleSetupWizard.interactive.autoUpdateNote')}
          </p>
        </div>
      )}
    </div>
  );
}

// ─── Configure Panel (for connected state) ───────────────────────────────────

function ConfigurePanel({
  status,
  onConfigure,
  isLoading,
}: {
  status: TailscaleSetupStatus;
  onConfigure: (data: TailscaleConfigureRequest) => void;
  isLoading: boolean;
}) {
  const { t } = useTranslation('vpn');
  const [hostname, setHostname] = useState(status.hostname || '');
  const [acceptRoutes, setAcceptRoutes] = useState(true);
  const [advertiseRoutes, setAdvertiseRoutes] = useState('');
  const [acceptDns, setAcceptDns] = useState(true);
  const [advertiseExitNode, setAdvertiseExitNode] = useState(false);
  const [shieldsUp, setShieldsUp] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onConfigure({
      hostname: hostname.trim() || undefined,
      accept_routes: acceptRoutes,
      advertise_routes: advertiseRoutes ? advertiseRoutes.split(',').map(r => r.trim()).filter(Boolean) : undefined,
      accept_dns: acceptDns,
      advertise_exit_node: advertiseExitNode,
      shields_up: shieldsUp,
    });
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <Settings className="h-4 w-4" />
          {t('TailscaleSetupWizard.configure.title')}
        </CardTitle>
        <CardDescription>{t('TailscaleSetupWizard.configure.description')}</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label>{t('TailscaleSetupWizard.fields.hostname')}</Label>
            <Input
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              className="font-mono text-sm"
              placeholder={status.hostname || 'freesdn-controller'}
            />
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label className="text-sm">{t('TailscaleSetupWizard.options.acceptRoutes.label')}</Label>
              <p className="text-xs text-muted-foreground">{t('TailscaleSetupWizard.options.acceptRoutes.description')}</p>
            </div>
            <Switch checked={acceptRoutes} onCheckedChange={setAcceptRoutes} />
          </div>

          <div className="space-y-2">
            <Label>{t('TailscaleSetupWizard.options.advertiseRoutes.label')}</Label>
            <Input
              value={advertiseRoutes}
              onChange={(e) => setAdvertiseRoutes(e.target.value)}
              className="font-mono text-sm"
              placeholder="10.0.0.0/24, 192.168.1.0/24"
            />
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label className="text-sm">{t('TailscaleSetupWizard.options.acceptDns.label')}</Label>
              <p className="text-xs text-muted-foreground">{t('TailscaleSetupWizard.options.acceptDns.description')}</p>
            </div>
            <Switch checked={acceptDns} onCheckedChange={setAcceptDns} />
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label className="text-sm">{t('TailscaleSetupWizard.options.exitNode.label')}</Label>
              <p className="text-xs text-muted-foreground">{t('TailscaleSetupWizard.options.exitNode.description')}</p>
            </div>
            <Switch checked={advertiseExitNode} onCheckedChange={setAdvertiseExitNode} />
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label className="text-sm">{t('TailscaleSetupWizard.options.shieldsUp.label')}</Label>
              <p className="text-xs text-muted-foreground">{t('TailscaleSetupWizard.options.shieldsUp.description')}</p>
            </div>
            <Switch checked={shieldsUp} onCheckedChange={setShieldsUp} />
          </div>

          <Button type="submit" disabled={isLoading} className="w-full">
            {isLoading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                {t('TailscaleSetupWizard.configure.applying')}
              </>
            ) : (
              <>
                <Settings className="mr-2 h-4 w-4" />
                {t('TailscaleSetupWizard.configure.apply')}
              </>
            )}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

// ─── Main Export: TailscaleSetupWizard ────────────────────────────────────────

export default function TailscaleSetupWizard() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { t } = useTranslation('vpn');
  const [loginUrl, setLoginUrl] = useState<string | undefined>();
  const [authMethod, setAuthMethod] = useState<'authkey' | 'browser'>('authkey');

  // ── Query: Tailscale setup status (polls every 5s) ──
  const {
    data: setupStatus,
    isLoading: statusLoading,
    isError: statusError,
    refetch: refetchStatus,
  } = useQuery({
    queryKey: ['tailscaleSetupStatus'],
    queryFn: async () => (await vpnApi.tailscale.setup.getStatus()).data,
    refetchInterval: (query) => query.state.data?.state === 'connected' ? 30000 : 5000,
  });

  // Clear login URL when state transitions to connected
  useEffect(() => {
    if (setupStatus?.state === 'connected') {
      setLoginUrl(undefined);
    }
  }, [setupStatus?.state]);

  // ── Mutations ──

  const startDaemonMutation = useMutation({
    mutationFn: async () => (await vpnApi.tailscale.setup.startDaemon()).data,
    onSuccess: (data) => {
      toast({ title: data.success ? t('TailscaleSetupWizard.toast.daemonStarted') : t('TailscaleSetupWizard.toast.warning'), description: data.message });
      refetchStatus();
    },
    onError: (err: any) => {
      toast({ title: t('TailscaleSetupWizard.toast.startDaemonFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const authKeyLoginMutation = useMutation({
    mutationFn: async (data: TailscaleAuthKeyLogin) => (await vpnApi.tailscale.setup.loginAuthKey(data)).data,
    onSuccess: (data) => {
      if (data.success) {
        toast({ title: t('TailscaleSetupWizard.toast.connected'), description: t('TailscaleSetupWizard.toast.joinedTailnet', { hostname: data.hostname || 'freesdn-controller' }) });
        queryClient.invalidateQueries({ queryKey: ['tailscaleStatus'] });
      } else {
        toast({ title: t('TailscaleSetupWizard.toast.loginFailed'), description: data.message, variant: 'destructive' });
      }
      refetchStatus();
    },
    onError: (err: any) => {
      toast({ title: t('TailscaleSetupWizard.toast.authFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const interactiveLoginMutation = useMutation({
    mutationFn: async (hostname?: string) =>
      (await vpnApi.tailscale.setup.loginInteractive({ hostname, accept_routes: true })).data,
    onSuccess: (data) => {
      if (data.login_url) {
        setLoginUrl(data.login_url);
        toast({ title: t('TailscaleSetupWizard.toast.loginUrlReady'), description: t('TailscaleSetupWizard.toast.loginUrlReadyDescription') });
      } else if (data.success) {
        toast({ title: t('TailscaleSetupWizard.toast.connected'), description: data.message });
      }
      refetchStatus();
    },
    onError: (err: any) => {
      toast({ title: t('TailscaleSetupWizard.toast.interactiveLoginFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const configureMutation = useMutation({
    mutationFn: async (data: TailscaleConfigureRequest) => (await vpnApi.tailscale.setup.configure(data)).data,
    onSuccess: (data) => {
      toast({ title: data.success ? t('TailscaleSetupWizard.toast.configured') : t('TailscaleSetupWizard.toast.warning'), description: data.message });
      refetchStatus();
      queryClient.invalidateQueries({ queryKey: ['tailscaleStatus'] });
    },
    onError: (err: any) => {
      toast({ title: t('TailscaleSetupWizard.toast.configureFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const disconnectMutation = useMutation({
    mutationFn: async () => (await vpnApi.tailscale.setup.disconnect()).data,
    onSuccess: (data) => {
      toast({ title: t('TailscaleSetupWizard.toast.disconnected'), description: data.message });
      refetchStatus();
      queryClient.invalidateQueries({ queryKey: ['tailscaleStatus'] });
    },
    onError: (err: any) => {
      toast({ title: t('TailscaleSetupWizard.toast.disconnectFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const reconnectMutation = useMutation({
    mutationFn: async () => (await vpnApi.tailscale.setup.reconnect()).data,
    onSuccess: (data) => {
      toast({ title: data.success ? t('TailscaleSetupWizard.toast.reconnected') : t('TailscaleSetupWizard.toast.warning'), description: data.message });
      refetchStatus();
      queryClient.invalidateQueries({ queryKey: ['tailscaleStatus'] });
    },
    onError: (err: any) => {
      toast({ title: t('TailscaleSetupWizard.toast.reconnectFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const logoutMutation = useMutation({
    mutationFn: async () => (await vpnApi.tailscale.setup.logout()).data,
    onSuccess: (data) => {
      toast({ title: t('TailscaleSetupWizard.toast.loggedOut'), description: data.message });
      setLoginUrl(undefined);
      refetchStatus();
      queryClient.invalidateQueries({ queryKey: ['tailscaleStatus'] });
    },
    onError: (err: any) => {
      toast({ title: t('TailscaleSetupWizard.toast.logoutFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── Loading state ──

  if (statusLoading && !setupStatus) {
    return (
      <Card className="p-12">
        <div className="flex flex-col items-center justify-center text-center">
          <Loader2 className="h-8 w-8 text-blue-500 animate-spin mb-4" />
          <h3 className="text-lg font-semibold mb-2">{t('TailscaleSetupWizard.loading.title')}</h3>
          <p className="text-muted-foreground">{t('TailscaleSetupWizard.loading.description')}</p>
        </div>
      </Card>
    );
  }

  if (statusError || !setupStatus) {
    return (
      <Card className="p-12">
        <div className="flex flex-col items-center justify-center text-center">
          <AlertTriangle className="h-8 w-8 text-muted-foreground/50 mb-4" />
          <h3 className="text-lg font-semibold mb-2">{t('TailscaleSetupWizard.statusError.title')}</h3>
          <p className="text-muted-foreground mb-4">{t('TailscaleSetupWizard.statusError.description')}</p>
          <Button variant="outline" onClick={() => refetchStatus()}>
            <RefreshCw className="mr-2 h-4 w-4" />
            {t('TailscaleSetupWizard.actions.retry')}
          </Button>
        </div>
      </Card>
    );
  }

  const state = setupStatus.state;

  // ── Not Installed State ──
  if (state === 'not_installed') {
    return (
      <div className="space-y-4">
        <SetupStatusBanner status={setupStatus} />
        <Card className="p-8">
          <div className="flex flex-col items-center justify-center text-center">
            <Shield className="h-12 w-12 text-muted-foreground/50 mb-4" />
            <h3 className="text-lg font-semibold mb-2">{t('TailscaleSetupWizard.notInstalled.title')}</h3>
            <p className="text-muted-foreground max-w-md mb-4">
              {t('TailscaleSetupWizard.notInstalled.description')}
            </p>
            <code className="text-xs bg-muted rounded px-3 py-2 font-mono">
              docker compose build api && docker compose up -d api
            </code>
          </div>
        </Card>
      </div>
    );
  }

  // ── Daemon Stopped State ──
  if (state === 'daemon_stopped') {
    return (
      <div className="space-y-4">
        <SetupStatusBanner status={setupStatus} />
        <Card className="p-8">
          <div className="flex flex-col items-center justify-center text-center">
            <Power className="h-12 w-12 text-orange-500/50 mb-4" />
            <h3 className="text-lg font-semibold mb-2">{t('TailscaleSetupWizard.daemonStopped.title')}</h3>
            <p className="text-muted-foreground max-w-md mb-6">
              {t('TailscaleSetupWizard.daemonStopped.descriptionPrefix')}{' '}
              <code className="bg-muted px-1 rounded text-xs">tailscaled</code>{' '}
              {t('TailscaleSetupWizard.daemonStopped.descriptionSuffix')}
            </p>
            <Button
              size="lg"
              onClick={() => startDaemonMutation.mutate()}
              disabled={startDaemonMutation.isPending}
            >
              {startDaemonMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  {t('TailscaleSetupWizard.daemonStopped.starting')}
                </>
              ) : (
                <>
                  <Zap className="mr-2 h-4 w-4" />
                  {t('TailscaleSetupWizard.daemonStopped.start')}
                </>
              )}
            </Button>
          </div>
        </Card>
      </div>
    );
  }

  // ── Needs Login / Awaiting Auth ──
  if (state === 'needs_login' || state === 'awaiting_auth') {
    return (
      <div className="space-y-4">
        <SetupStatusBanner status={setupStatus} />

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5 text-blue-500" />
              {t('TailscaleSetupWizard.authenticate.title')}
            </CardTitle>
            <CardDescription>
              {t('TailscaleSetupWizard.authenticate.description')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs value={authMethod} onValueChange={(v) => setAuthMethod(v as 'authkey' | 'browser')} className="w-full">
              <TabsList className="grid w-full grid-cols-2 mb-4">
                <TabsTrigger value="authkey" className="flex items-center gap-1.5">
                  <Key className="h-3.5 w-3.5" />
                  {t('TailscaleSetupWizard.authenticate.authKeyTab')}
                </TabsTrigger>
                <TabsTrigger value="browser" className="flex items-center gap-1.5">
                  <Globe className="h-3.5 w-3.5" />
                  {t('TailscaleSetupWizard.authenticate.browserTab')}
                </TabsTrigger>
              </TabsList>

              <TabsContent value="authkey">
                <AuthKeyLoginForm
                  onLogin={authKeyLoginMutation.mutate}
                  isLoading={authKeyLoginMutation.isPending}
                />
              </TabsContent>

              <TabsContent value="browser">
                <InteractiveLoginPanel
                  loginUrl={loginUrl || setupStatus.login_url}
                  onStartLogin={(hostname) => interactiveLoginMutation.mutate(hostname)}
                  isLoading={interactiveLoginMutation.isPending}
                />
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>

        <Alert>
          <Info className="h-4 w-4" />
          <AlertDescription>
            <strong>{t('TailscaleSetupWizard.authKeyTip.label')}</strong> {t('TailscaleSetupWizard.authKeyTip.prefix')}{' '}
            <a href="https://login.tailscale.com/admin/settings/keys" target="_blank" rel="noopener noreferrer" className="underline">
              {t('TailscaleSetupWizard.adminConsole')}
            </a>
            {t('TailscaleSetupWizard.authKeyTip.suffix')}
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  // ── Connected State ──
  if (state === 'connected') {
    return (
      <div className="space-y-4">
        <SetupStatusBanner status={setupStatus} />
        <ConnectedInfoPanel status={setupStatus} />

        {/* Actions Bar */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Zap className="h-4 w-4" />
              {t('TailscaleSetupWizard.quickActions.title')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => refetchStatus()}
              >
                <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
                {t('TailscaleSetupWizard.quickActions.refreshStatus')}
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="text-orange-600 hover:text-orange-600"
                onClick={() => {
                  if (confirm(t('TailscaleSetupWizard.confirm.disconnect'))) {
                    disconnectMutation.mutate();
                  }
                }}
                disabled={disconnectMutation.isPending}
              >
                {disconnectMutation.isPending ? (
                  <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                ) : (
                  <WifiOff className="mr-1.5 h-3.5 w-3.5" />
                )}
                {t('TailscaleSetupWizard.quickActions.disconnect')}
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="text-destructive hover:text-destructive"
                onClick={() => {
                  if (confirm(t('TailscaleSetupWizard.confirm.logout'))) {
                    logoutMutation.mutate();
                  }
                }}
                disabled={logoutMutation.isPending}
              >
                {logoutMutation.isPending ? (
                  <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                ) : (
                  <LogOut className="mr-1.5 h-3.5 w-3.5" />
                )}
                {t('TailscaleSetupWizard.quickActions.logout')}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Configuration */}
        <ConfigurePanel
          status={setupStatus}
          onConfigure={configureMutation.mutate}
          isLoading={configureMutation.isPending}
        />
      </div>
    );
  }

  // ── Error / Fallback ──
  return (
    <div className="space-y-4">
      <SetupStatusBanner status={setupStatus} />
      <Card className="p-8">
        <div className="flex flex-col items-center justify-center text-center">
          <AlertTriangle className="h-12 w-12 text-destructive/50 mb-4" />
          <h3 className="text-lg font-semibold mb-2">{t('TailscaleSetupWizard.unexpectedState.title')}</h3>
          <p className="text-muted-foreground max-w-md mb-2">
            {t('TailscaleSetupWizard.unexpectedState.descriptionPrefix')}{' '}
            <code className="bg-muted px-1 rounded text-xs">{state}</code>.
            {setupStatus.message && ` ${setupStatus.message}`}
          </p>
          <div className="flex gap-2 mt-4">
            <Button variant="outline" onClick={() => refetchStatus()}>
              <RefreshCw className="mr-2 h-4 w-4" />
              {t('TailscaleSetupWizard.actions.refresh')}
            </Button>
            <Button
              variant="outline"
              onClick={() => reconnectMutation.mutate()}
              disabled={reconnectMutation.isPending}
            >
              {reconnectMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Wifi className="mr-2 h-4 w-4" />
              )}
              {t('TailscaleSetupWizard.actions.reconnect')}
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
