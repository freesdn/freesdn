// SPDX-License-Identifier: AGPL-3.0-only
import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { gatewayApi } from '@/lib/api';
import { saveGatewayConfiguration } from '@/lib/gateway-config-download';
import { useToast } from '@/hooks/use-toast';

/** Keep secret export responses out of query and mutation caches. */
export function useGatewayConfigDownload(gatewayId: string | undefined) {
  const { toast } = useToast();
  const { t } = useTranslation('firewall');
  const active = useRef<{ id: string; controller: AbortController } | null>(null);
  const [pendingId, setPendingId] = useState<string | null>(null);

  useEffect(() => () => {
    const operation = active.current;
    if (operation && operation.id === gatewayId) {
      operation.controller.abort();
      active.current = null;
    }
  }, [gatewayId]);

  const download = useCallback(async () => {
    if (!gatewayId || active.current?.id === gatewayId) return;
    active.current?.controller.abort();
    const operation = { id: gatewayId, controller: new AbortController() };
    active.current = operation;
    setPendingId(gatewayId);
    try {
      const response = await gatewayApi.downloadConfig(gatewayId, operation.controller.signal);
      if (active.current !== operation || operation.controller.signal.aborted) return;
      saveGatewayConfiguration(response.data, gatewayId);
      toast({
        title: t('GatewayDetailPage.download.started', { defaultValue: 'Configuration download started' }),
        description: t('GatewayDetailPage.download.protect', {
          defaultValue: 'Protect this file: it may contain gateway passwords, keys and other secrets.',
        }),
      });
    } catch {
      if (active.current !== operation || operation.controller.signal.aborted) return;
      toast({
        title: t('GatewayDetailPage.download.failed', { defaultValue: 'Configuration download failed' }),
        description: t('GatewayDetailPage.download.failureHelp', {
          defaultValue: 'The configuration could not be downloaded. Check your permissions and the gateway connection.',
        }),
        variant: 'destructive',
      });
    } finally {
      if (active.current === operation) {
        active.current = null;
        setPendingId(null);
      }
    }
  }, [gatewayId, t, toast]);

  return { download, isDownloading: !!gatewayId && pendingId === gatewayId };
}
