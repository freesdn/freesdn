// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useTranslation } from 'react-i18next';
import { RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { CardContent } from '@/components/ui/card';

export function GatewayLiveReadNotice({ loading = false, onRetry }: { loading?: boolean; onRetry?: () => void }) {
  const { t } = useTranslation('firewall');
  return <CardContent>
    {loading ? <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground"><RefreshCw className="h-4 w-4 animate-spin" />{t('GatewayLiveRead.loading')}</p>
      : <div role="alert" className="space-y-3"><p className="text-sm text-muted-foreground">{t('GatewayLiveRead.unavailable')}</p>{onRetry && <Button variant="outline" size="sm" onClick={onRetry}>{t('GatewayLiveRead.retry')}</Button>}</div>}
  </CardContent>;
}
