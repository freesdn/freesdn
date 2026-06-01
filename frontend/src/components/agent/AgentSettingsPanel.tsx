// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * AgentSettingsPanel, server-side configurable settings for a single agent.
 *
 * Covers the fields backed by the DB (the agent's local config.json
 * for things like auto_update_interval is daemon-side and not editable
 * from the web UI):
 *  - description: free-text label
 *  - is_enabled: master switch, disabling stops task dispatch
 *  - poll_interval: legacy REST polling interval (still used by some
 *    agent flavours, mostly historical now that WS push is default)
 *  - offline_threshold_seconds: when the cleanup task flips status
 *    to offline and notification_channels fire (chapter 11 alert)
 *  - notification_channels: email / slack endpoints
 *
 * Pairs with the Configure-alerts dialog on Overview: this gives the
 * full surface in one place.
 */

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Save, Loader2, AlertTriangle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { useToast } from '@/hooks/use-toast';
import { agentsApi } from '@/lib/api/agents';
import type { AgentDetail } from '@/lib/api/types';

interface Props {
  agent: AgentDetail;
}

export function AgentSettingsPanel({ agent }: Props) {
  const { t } = useTranslation('common');
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Mirror current agent state, re-sync if a parent refresh swaps it
  // out from under us.
  const [description, setDescription] = useState(agent.description || '');
  const [isEnabled, setIsEnabled] = useState(agent.is_enabled);
  const [pollInterval, setPollInterval] = useState(agent.poll_interval || 30);
  const [offlineThreshold, setOfflineThreshold] = useState(
    agent.offline_threshold_seconds ?? 180,
  );
  const ch = (agent.notification_channels || {}) as Record<string, any>;
  const [emailRecipients, setEmailRecipients] = useState(
    (ch.email?.to as string[] | undefined)?.join(', ') || '',
  );
  const [slackChannel, setSlackChannel] = useState(
    (ch.slack?.channel as string | undefined) || '',
  );
  const [webhookUrl, setWebhookUrl] = useState(
    (ch.webhook?.url as string | undefined) || '',
  );

  useEffect(() => {
    setDescription(agent.description || '');
    setIsEnabled(agent.is_enabled);
    setPollInterval(agent.poll_interval || 30);
    setOfflineThreshold(agent.offline_threshold_seconds ?? 180);
    const ch2 = (agent.notification_channels || {}) as Record<string, any>;
    setEmailRecipients((ch2.email?.to as string[] | undefined)?.join(', ') || '');
    setSlackChannel((ch2.slack?.channel as string | undefined) || '');
    setWebhookUrl((ch2.webhook?.url as string | undefined) || '');
  }, [agent.id]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      const channels: Record<string, unknown> = {};
      const emails = emailRecipients
        .split(/[,;\s]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      if (emails.length > 0) channels.email = { to: emails };
      if (slackChannel.trim()) channels.slack = { channel: slackChannel.trim() };
      if (webhookUrl.trim()) channels.webhook = { url: webhookUrl.trim() };

      return agentsApi.update(agent.id, {
        description,
        is_enabled: isEnabled,
        poll_interval: pollInterval,
        notification_channels: channels,
        offline_threshold_seconds: offlineThreshold,
      } as any);
    },
    onSuccess: () => {
      toast({ title: t('AgentSettingsPanel.toasts.saved.title') });
      queryClient.invalidateQueries({ queryKey: ['agent-detail', agent.id] });
      queryClient.invalidateQueries({ queryKey: ['agents'] });
    },
    onError: (err: any) => {
      toast({
        title: t('AgentSettingsPanel.toasts.saveFailed.title'),
        description: err?.response?.data?.detail || String(err),
        variant: 'destructive',
      });
    },
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>{t('AgentSettingsPanel.general.title')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label htmlFor="agent-desc">{t('AgentSettingsPanel.general.descriptionLabel')}</Label>
            <Textarea
              id="agent-desc"
              placeholder={t('AgentSettingsPanel.general.descriptionPlaceholder')}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
              maxLength={2000}
            />
          </div>
          <div className="flex items-center justify-between rounded border p-3">
            <div>
              <Label htmlFor="agent-enabled" className="text-sm font-medium">
                {t('AgentSettingsPanel.general.enabledLabel')}
              </Label>
              <div className="text-xs text-muted-foreground">
                {t('AgentSettingsPanel.general.enabledHelp')}
              </div>
            </div>
            <Switch
              id="agent-enabled"
              checked={isEnabled}
              onCheckedChange={setIsEnabled}
            />
          </div>
          <div>
            <Label htmlFor="agent-poll">{t('AgentSettingsPanel.general.pollIntervalLabel')}</Label>
            <Input
              id="agent-poll"
              type="number"
              min={10}
              max={3600}
              value={pollInterval}
              onChange={(e) =>
                setPollInterval(parseInt(e.target.value, 10) || 30)
              }
            />
            <div className="text-xs text-muted-foreground mt-1">
              {t('AgentSettingsPanel.general.pollIntervalHelp')}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('AgentSettingsPanel.offlineAlerts.title')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label htmlFor="agent-threshold">
              {t('AgentSettingsPanel.offlineAlerts.thresholdLabel')}
            </Label>
            <Input
              id="agent-threshold"
              type="number"
              min={60}
              max={86400}
              value={offlineThreshold}
              onChange={(e) =>
                setOfflineThreshold(parseInt(e.target.value, 10) || 180)
              }
            />
            <div className="text-xs text-muted-foreground mt-1">
              {t('AgentSettingsPanel.offlineAlerts.thresholdHelp')}
            </div>
          </div>
          <div>
            <Label htmlFor="agent-email">{t('AgentSettingsPanel.offlineAlerts.emailLabel')}</Label>
            <Input
              id="agent-email"
              placeholder={t('AgentSettingsPanel.offlineAlerts.emailPlaceholder')}
              value={emailRecipients}
              onChange={(e) => setEmailRecipients(e.target.value)}
            />
            <div className="text-xs text-muted-foreground mt-1">
              {t('AgentSettingsPanel.offlineAlerts.emailHelp')}
            </div>
          </div>
          <div>
            <Label htmlFor="agent-slack">{t('AgentSettingsPanel.offlineAlerts.slackLabel')}</Label>
            <Input
              id="agent-slack"
              placeholder="#alerts"
              value={slackChannel}
              onChange={(e) => setSlackChannel(e.target.value)}
            />
          </div>
          <div>
            <Label htmlFor="agent-webhook">{t('AgentSettingsPanel.offlineAlerts.webhookLabel')}</Label>
            <Input
              id="agent-webhook"
              placeholder="https://example.com/hook"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
            />
          </div>
        </CardContent>
      </Card>

      {agent.offline_notified_at ? (
        <Card className="border-amber-500 bg-amber-50 dark:bg-amber-950/20">
          <CardContent className="p-3 flex items-center gap-3 text-sm">
            <AlertTriangle className="h-4 w-4 text-amber-600 flex-shrink-0" />
            <div>
              <div className="font-medium">{t('AgentSettingsPanel.lastAlert.title')}</div>
              <div className="text-xs text-muted-foreground">
                {t('AgentSettingsPanel.lastAlert.detail', {
                  timestamp: new Date(agent.offline_notified_at).toLocaleString(),
                })}
              </div>
            </div>
          </CardContent>
        </Card>
      ) : null}

      <div className="flex justify-end">
        <Button
          onClick={() => saveMutation.mutate()}
          disabled={saveMutation.isPending}
        >
          {saveMutation.isPending ? (
            <>
              <Loader2 className="h-4 w-4 mr-1 animate-spin" />
              {t('AgentSettingsPanel.actions.saving')}
            </>
          ) : (
            <>
              <Save className="h-4 w-4 mr-1" />
              {t('AgentSettingsPanel.actions.save')}
            </>
          )}
        </Button>
      </div>
    </div>
  );
}
